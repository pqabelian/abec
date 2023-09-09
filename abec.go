// Copyright (c) 2022-2023 The Abelian Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/blockchain/indexers"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/limits"
	"github.com/abesuite/abec/mempool"
	"github.com/abesuite/abec/wire"
	"github.com/shirou/gopsutil/v3/mem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
)

const (
	// blockDbNamePrefix is the prefix for the block database name.  The
	// database type is appended to this value to form the full block
	// database name.
	blockDbNamePrefix = "blocks"
)

var (
	cfg *config
)

// winServiceMain is only invoked on Windows.  It detects when abec is running
// as a service and reacts accordingly.
var winServiceMain func() (bool, error)

// abecMain is the real main function for abec.  It is necessary to work around
// the fact that deferred functions do not run when os.Exit() is called.  The
// optional serverChan parameter is mainly used by the service code to be
// notified with the server once it is setup so it can gracefully stop it when
// requested from the service control manager.
func abecMain(serverChan chan<- *server) error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Get a channel that will be closed when a shutdown signal has been
	// triggered either from an OS signal such as SIGINT (Ctrl+C) or from
	// another subsystem such as the RPC server.
	interrupt := interruptListener()
	defer abecLog.Info("Shutdown complete")

	// Show version at startup.
	abecLog.Infof("Version %s", version())

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			abecLog.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			abecLog.Errorf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			abecLog.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	// Return now if an interrupt signal was triggered.
	if interruptRequested(interrupt) {
		return nil
	}

	// Load the block database.
	db, err := loadBlockDB()
	if err != nil {
		abecLog.Errorf("%v", err)
		return err
	}
	defer func() {
		// Ensure the database is sync'd and closed on shutdown.
		abecLog.Infof("Gracefully shutting down the database...")
		db.Close()
	}()

	// Return now if an interrupt signal was triggered.
	if interruptRequested(interrupt) {
		return nil
	}

	// Drop indexes and exit if requested.
	if cfg.DropTxIndex {
		if err := indexers.DropTxIndex(db, interrupt); err != nil {
			abecLog.Errorf("%v", err)
			return err
		}

		return nil
	}

	// check the memory
	v, err := mem.VirtualMemory()
	if err != nil {
		abecLog.Warnf("fail to acquire system info %v, use the default memory configuration", err)
	} else {
		if v.Total >= 32*1024*1024*1024 {
			blockchain.MaxOrphanBlocks = 160
			mempool.MaxTransactionInMemoryNum = 1600
		} else if v.Total >= 16*1024*1024*1024 {
			blockchain.MaxOrphanBlocks = 80
			mempool.MaxTransactionInMemoryNum = 800
		} else if v.Total >= 8*1024*1024*1024 {
			blockchain.MaxOrphanBlocks = 40
			mempool.MaxTransactionInMemoryNum = 400
		} else if v.Total >= 4*1024*1024*1024 {
			blockchain.MaxOrphanBlocks = 20
			mempool.MaxTransactionInMemoryNum = 200
		} else {
			blockchain.MaxOrphanBlocks = 10
			mempool.MaxTransactionInMemoryNum = 100
		}
	}

	// Create P2P server and start it.
	server, err := newServer(cfg.Listeners, cfg.AgentBlacklist,
		cfg.AgentWhitelist, db, activeNetParams.Params, interrupt)
	if err != nil {
		// TODO: this logging could do with some beautifying.
		abecLog.Errorf("Unable to start server on %v: %v",
			cfg.Listeners, err)
		return err
	}
	defer func() {
		abecLog.Infof("Gracefully shutting down the server...")
		server.Stop()
		server.WaitForShutdown()
		srvrLog.Infof("Server shutdown complete")
	}()
	if cfg.AllowDiskCacheTx {
		defer func() {
			if server.txCacheRotator != nil {
				server.txCacheRotator.Close()
			}
			// Clear the transaction cache file
			os.RemoveAll(cfg.CacheTxDir)
		}()
	}
	server.Start() //Start the p2p server
	if serverChan != nil {
		serverChan <- server
	}

	// Wait until the interrupt signal is received from an OS signal or
	// shutdown is requested through one of the subsystems such as the RPC
	// server.
	<-interrupt
	return nil
}

// removeRegressionDB removes the existing regression test database if running
// in regression test mode and it already exists.
func removeRegressionDB(dbPath string) error {
	// Don't do anything if not in regression test mode.
	if !cfg.RegressionTest {
		return nil
	}

	// Remove the old regression test database if it already exists.
	fi, err := os.Stat(dbPath)
	if err == nil {
		abecLog.Infof("Removing regression test database from '%s'", dbPath)
		if fi.IsDir() {
			err := os.RemoveAll(dbPath)
			if err != nil {
				return err
			}
		} else {
			err := os.Remove(dbPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// dbPath returns the path to the block database given a database type.
func blockDbPath(dbType string) string {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + dbType
	if dbType == "sqlite" {
		dbName = dbName + ".db"
	}
	dbPath := filepath.Join(cfg.DataDir, dbName)
	return dbPath
}

// warnMultipleDBs shows a warning if multiple block database types are detected.
// This is not a situation most users want.  It is handy for development however
// to support multiple side-by-side databases.
func warnMultipleDBs() {
	// This is intentionally not using the known db types which depend
	// on the database types compiled into the binary since we want to
	// detect legacy db types as well.
	dbTypes := []string{"ffldb", "leveldb", "sqlite"}
	duplicateDbPaths := make([]string, 0, len(dbTypes)-1)
	for _, dbType := range dbTypes {
		if dbType == cfg.DbType {
			continue
		}

		// Store db path as a duplicate db if it exists.
		dbPath := blockDbPath(dbType)
		if fileExists(dbPath) {
			duplicateDbPaths = append(duplicateDbPaths, dbPath)
		}
	}

	// Warn if there are extra databases.
	if len(duplicateDbPaths) > 0 {
		selectedDbPath := blockDbPath(cfg.DbType)
		abecLog.Warnf("WARNING: There are multiple block chain databases "+
			"using different database types.\nYou probably don't "+
			"want to waste disk space by having more than one.\n"+
			"Your current database is located at [%v].\nThe "+
			"additional database is located at %v", selectedDbPath,
			duplicateDbPaths)
	}
}

// loadBlockDB loads (or creates when needed) the block database taking into
// account the selected database backend and returns a handle to it.  It also
// contains additional logic such warning the user if there are multiple
// databases which consume space on the file system and ensuring the regression
// test database is clean when in regression test mode.
func loadBlockDB() (database.DB, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.  We also don't want to worry about the multiple
	// database type warnings when running with the memory database.
	if cfg.DbType == "memdb" {
		abecLog.Infof("Creating block database in memory.")
		db, err := database.Create(cfg.DbType)
		if err != nil {
			return nil, err
		}
		return db, nil
	}

	warnMultipleDBs()

	// The database name is based on the database type.
	dbPath := blockDbPath(cfg.DbType)

	// The regression test is special in that it needs a clean database for
	// each run, so remove it now if it already exists.
	removeRegressionDB(dbPath)

	abecLog.Infof("Loading block database from '%s'", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net, cfg.nodeType, cfg.trustLevel)
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net, cfg.nodeType, cfg.trustLevel)
		if err != nil {
			return nil, err
		}
	}

	var nodeType wire.NodeType
	var trustLevel wire.TrustLevel
	err = db.View(func(dbTx database.Tx) error {
		var err error
		nodeType, err = dbTx.FetchNodeType()
		return err
	})
	if err != nil {
		return nil, err
	}
	err = db.View(func(dbTx database.Tx) error {
		var err error
		trustLevel, err = dbTx.FetchTrustLevel()
		return err
	})
	if err != nil {
		return nil, err
	}

	if cfg.nodeType != nodeType {
		fmt.Printf("Your current node type is %s, but specified node type is %s, do you want to continue"+
			" (Y/N)? ", nodeType.String(), cfg.nodeType.String())
		op := "N"
		fmt.Scanln(&op)
		if strings.TrimSpace(strings.ToLower(op)) != "y" && strings.TrimSpace(strings.ToLower(op)) != "yes" {
			os.Exit(0)
		}
	}

	// Insert new node type into database.
	err = db.Update(func(dbTx database.Tx) error {
		var err error
		err = dbTx.StoreNodeType(cfg.nodeType)
		return err
	})

	abecLog.Infof("Node type: %v", cfg.nodeType.String())
	//abecLog.Infof("Trust level: %v", trustLevel.String())
	//cfg.nodeType = nodeType
	cfg.trustLevel = trustLevel

	var witnessServiceHeight uint32
	err = db.View(func(dbTx database.Tx) error {
		var err error
		witnessServiceHeight, err = dbTx.FetchWitnessServiceHeight()
		return err
	})
	if err != nil {
		return nil, err
	}
	abecLog.Infof("Witness service height: %v", witnessServiceHeight)

	abecLog.Info("Block database loaded")
	return db, nil
}

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Block and transaction processing can cause bursty allocations.  This
	// limits the garbage collector from excessively overallocating during
	// bursts.  This value was arrived at with the help of profiling live
	// usage.
	debug.SetGCPercent(10)

	// Up some limits.
	if err := limits.SetLimits(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set limits: %v\n", err)
		os.Exit(1)
	}

	// Call serviceMain on Windows to handle running as a service.  When
	// the return isService flag is true, exit now since we ran as a
	// service.  Otherwise, just fall through to normal operation.
	if runtime.GOOS == "windows" {
		isService, err := winServiceMain()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if isService {
			os.Exit(0)
		}
	}

	// Work around defer not working after os.Exit()
	if err := abecMain(nil); err != nil {
		os.Exit(1)
	}
}
