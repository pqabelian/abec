// Copyright (c) 2020 The Abelian Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/blockchain/indexers"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/limits"
	"github.com/abesuite/abec/wire"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"
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

	// Perform upgrades to btcd as new versions require it.
	if err := doUpgrades(); err != nil {
		abecLog.Errorf("%v", err)
		return err
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
	//
	// NOTE: The order is important here because dropping the tx index also
	// drops the address index since it relies on it.
	if cfg.DropAddrIndex {
		if err := indexers.DropAddrIndex(db, interrupt); err != nil {
			abecLog.Errorf("%v", err)
			return err
		}

		return nil
	}
	if cfg.DropTxIndex {
		if err := indexers.DropTxIndex(db, interrupt); err != nil {
			abecLog.Errorf("%v", err)
			return err
		}

		return nil
	}
	// TODO(ABE): ABE does not support filter.
	//if cfg.DropCfIndex {
	//	if err := indexers.DropCfIndex(db, interrupt); err != nil {
	//		abecLog.Errorf("%v", err)
	//		return err
	//	}
	//
	//	return nil
	//}

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
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net)
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
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net)
		if err != nil {
			return nil, err
		}
	}

	abecLog.Info("Block database loaded")
	return db, nil
}

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	maddrStr := "000091d9fdd18a30089a132c04ee6528460fe9e647ce973e72c2ad0f605c5bbf8562f31cace2979c63073e2520e2ebd8509d2cd3c9e266721967cdb879420b8a53bf2b9194af353e5be8d0105d120569d8d72c3cbaaf1e48be3b42eeb27c62e21cab84471165ac7a405663c0979510da31131f8c90907ddcf6513dcdef8662c123211a9d621eb3f7501e3893bfbe45835ccb36fc20e3b6890391804921c83d6a3e0aadd9bb25c07ae41293fdcb2fe890ea2963e956e90d72d71f91067dc36b7693983c84b14c90c44def2ef659f567be3289af42b68183d7f4689e5c0367dfe8b5b832837ec66fa7859f02a2b656c0a04c0769ff45fee7a50a5c4f0f4a8375876a66e373d80c5853a9f959b041d9eb4b0d67679ec00aa1addd61a36f09b398562c4bb8c839549577c3206c09b3379b6739d6a950d0e6837caed2f5833cf603c7f0fed5ff6b69bbe36e12bbdc7241bd19a830680124684d0e092e426c4219e80d3e1f063259adabcf37afa1a4cfd2592f25bab7ef810a8fe19eed3cbd98853450b6964b275db000422feea110319fa5d8a91b131e7602c4b60aea54cdd42fb49e436e2d39fb225afbd8a8dc86b879b746c745f8a6ad17e6958677e4b6d77800639d6bd4f0b589a832b525a1fb848db1cf2e43f1c7a733a99ecb56215140c6097dce2c3d1f91b95dfb998d4284e8d4f7889c31d986461c42a90a19f05273591b882b0ee8c7e70130796fa971a43fc0f7d094f6d75a2a7ad307aa2f569ea56318fbaf08a345d8ac9d28d818b320d2b211ca383d78b49894fa609b6271e2ab4696dda43579bd1b948244e8a8e269820b0c13a71c713b014d52454a45ec3ce29941dde704d7872f9679fe7dc645f3b20c0671592df96944ba554540a900bbf12c4082510d8a2814bfcffb4d3e2eaa1e7abb93b45c709295e9a7cdea73516b012818e2e0ee2e3e427f297d6a0564d89ac9672a125b01d6019956c1d6939c1eb566a8f5db4a2680ae6fb575f47707be997c3530663e6208bf14e135613c95f86b65d6b490a7e46ee6ad1464226a188b64f515425e522bfb28fc37a34be26f0b4a43ebfb575c7e1a77629bdb9ac0122a411442ebbb5afd5374ab423810472b2cd3663e9261cad46d0b4d050fa80450dfa327db472b859f9b748033a1495f5f8ceefe1a2a7833cf0cb1774cf2cc929368fdb6c171fd1d8cb1878ae37fd693a7266152df1a63893b99b17b4021a8012bef5285568fd2dfb82d631872750ec1e763153af6878a8fb5791bc1697bb128ac7e8cef7f9612513507f0b982ec9cbb4504412007a9426291398b5d7d84d8cb68cb16049125d46221cd850d7c1b1cf81d9eebb2f2a49c6fadc9d87158cd585d9ba553c8eadd0f12de5d3f372bed40bde34055ab15fd5d232a8eac3981abf3164616c5cd3d6431441b466f00615b029dda2c7eefbc69a84114cdefa61aa97fe44b7aedeceaf63058d2ff366c7e1471ead55c69a0830146494fd8d3e9518ca77b592395333bb210a850476af060d7054e7d2a28e3d0591e830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005a18c8d25788245461776d2b99d4def46569165316d45679bea00fd7f64f46e71b4433797a36323d53b5c56a262c306aa31111779527a947e0373361417d318cf83827921e26ee104fa1e9cf71a8b1c216504fac7bd67611293c36b1bd91d352afb97b46af4ab6732f895e0099046bdb238e5ac4687e89597513b192c57cf9c46a4921a10b470fa205be1865cb74cd17320a843a06b7bb857cb920898fa6f1e6611079b2ffe5850e55e2547920a42f62b0ff3859c426883442eb742f10b830b86aa00a49997c3a69f23ba287093544ecc4e797f43e93ef520d21777e5360aa757cd61a86633400aaba6c43a8360145bdbb6232eced54df904d491b2b8d15179805c17695356d2f08d76260776911016a31b4b14d0183003c56100e13c227bf4551197363143b7d2074def212c5758fbbac09ab858a0c1386ef1e32ea9ff1a8357989ad66cb288d3437f297c83470ce169722dc1f6e163b282e66b57d16d631263e82da06468b217974f9680517fd141d4c0a8db435229fd2287f1ef3f81502ccb34661fe53747216aa4a1841e01ac4a92062e0831bb6950a0911cfd8454999dcf7f6d6a7a5d27e8a773c0984adede05b5eda7f71a688955f4d4b76f8cbc5514ed1579e41ec060383373c64ee52b4e1911db9467030c4b5aec64ab355534aa28768d56f47233f6d197ac2a2fe41a851206c053c57b192221168494a5944c219094e986f7d8080e948641fe38a96d43334ba3a4104c0695825803e833594f8bfa7b7cd7fc15b1a5bf16951251bd135f875f565a7e3810b5c42e4612ab4e4b828579e11b2622630c15d0fc9c800eba57e4b8363538e8754d4a0825559e85da302f39bfb635fd453570ce48bd75845f172381de1ba8a3f011dbe196b51b9bdbe2a809ee225632ab07e4f215e2cf6a08d3e621f4a10d1c08336e13577e724578816d0685a3b6c82284203ff494b2b18b1a2e7c3eda24e6a02b7558217a336191e25ae6032021f50673b1fae7458103f1b7c150c6b42f81033a9d3584ab05280e6734c1e5fb44b0501708dde525f6fe6ba19e7dfb35f7199e5d1cf75b0b2ec0e044a2c9014c302396ae71d3f3917f2fad1074d80bf8ce5e5f1cf1e45ee509484e09aff48419339f7508ff1ec42e834318c842d56074496f65117e6bd32710379698a9f92e572285a73f230adb498304046536bc19f916c8dfe04821ef91ad06bbd7c270d7c4945d7774b6d19e62455f0f738314c1e910b8828e059f27e248f62d2e2451525f800882c8f0bd41ab1507b320492cf2238aefe33193e0e1636889ede242e55f40000014a215c7baba648c4fb683b56852f2c1fc32932ea21620f0a27c28da6396a391b548c52624dc35226cc2349c2283bca2d2e571ab7d28a8c1a78729ca35be0aa293771dc8a6344a0c3e127716f22badde7b62a7b2b16405f6dc6aadc2c6c0e19cf6a322012853c1c241772c2cddf965a91a019534190eefd020e559516c14e8748090dd4ca3106d9bf403973d0324bc217f921339819a81456fc5de436aaec6de4a5dd9093221603c8a3b10278f81d88fa7e46a28201ef6c6036fcf6a44eb7775e5503de9c346046b05ea2e89836e5bc007a6dffd2801437d0937d406acb27b2f7b50bc70831b33314163387e661538bdadb97ec40005de73bbe71e2e79dc87b7b21728ee37357745c8a2d2ac5d1a876f52b5f72f34356c967f357d3cf3387a440f6bd40e5727aefc77a4fba14a10db553232236f429c60b0e11f0abae744509283c2f614fd4e13f0aeceb68f67250f35bb36503d5b00be8eb34e7edf5815093094c124f737492e09383b77bc4da7018d6657d37402acb8d18f71d50ee15b2d02cea519a1ed64a55366d6a906a0119707c185b0b97444d5131d034986584584c3c20c8a04fe806f8afd375c2271afa67f56a312449c844dca1c8693b7af55a7de4b3189c95574d4b4bcad42d181a465186ce5d81f867333fd678accda716b3197a2187de16e7a359fc2f6550dc7e64399d9067da509f8272c95c0914ae45b04ac13449ea57a50e323170a9c1b312064e2287d37da9d4690fdb934be40cac9e7dcf4e5d05c17572ab0686d626af21ce040a263141e1c6d7feb9516517f4cb2c27742e032bd36d878044ad0c79241b81813d81cda8c03190944b9ce33aa36a177e2d119d835ca05c17f757d3d12340165071a9d68f5d52b23a3a53f397917ca57798567b16eaa7740314d56049c68941803454039b7869f966363458789944a9f0f042908b790558168dfaaed69aa6fe2c5dd1502cc02bb2e4691a00ca0896ac0cca7d5a23d560a336018746c1f49a9d0613ebca627c4568fe25829fe045f3593ad3f5e5d1b73bd8c5465bc58b37ab057bf3b51fe41fc73f731edaf897d7476819112140a2a46125a9807568bbc07704ff531813e71b873f413fa171068c16ac6d957481625af8703a92e601f7ba064c6c51943666a4c419d4f25a1f8644e7b61436dd23b9d4fc66de3f1dd42e440781b50f541617c5966056e05e782677645e42f368e55a370618b982f001c80e28eeda22b2f5750c66fe73f79cc3e695575fd8dcc4f0c157ad8c31569d04dda57d636e10dc8d21cf30b0a6845b6ecd88516224a9b26f609320f8021b2d6e0131700c8a919af371580cd2c636637745eb24ebed226193a5fd6b4e9ebe0f9b66ca61f31f3ec8f777c549c9e034408e5456b5fa2bec684cbb38d7c67eb6a078aa5f4437f1c1222427cf6da416148443cf3ebf0ffc81271abfd031d939914a0733412e79ce48867405aef97c3bab0f9ab8c446e32451b59f1a59e553502555b4e21b7912e3bf5c732ee3c7b0f79f6b0010d784730c14d0fd643655868e01603024140c7f26e2d3c042b388404749d54bb6bc056610ac7160cfb7ad7283133b247739958c0d0514b5c42585827b0418116883fa1ee71635450547ac2123f4520d55100f2c876e903cc3563b556cf6a3a781d70a56064c085f157d3a4934c1361423813a125071e3acd4f24589c38b4aa00d0d22a482e93c2967cc4795b4e03a6e2f3b522227051b7cb871a52fb0fec006394b3e2aace594821280153a2f78a6cc055ff9f83c4087fa9007a6238f5e2fda38ded7cd36420b8b5a1a7e43cd055700733b71f7f75a1e2778879fb24063896eb03995a6253fd75169a34c633184eb6452cf021de2d1723232180e1867fe86597c77b3167005bcd28f24a35777d72f015f93ff156268386f9c80d3594573b3e368dd12131f119c40dd508e9bcc3f96b5f6ca4f28909bd0616af7eb544097ed94c78f5e7278724ce77853f25ad712bb4c5d6d26327ecc7613f9198e1688a958399eff821251525940419b969274034bd770181e4b8dd6d3b4074253a2ab9704531a110854c2bd784f14707be97f547bddf206ecd06439b4dc2eb616c832e4384fff64ccb5a3dcae07917c4c9b71ca032d3433f91d3eb04993eb2751cc6b18e79b9afe348fded5aca21c39dc7f72b2f4c3b354a9774c4bb49c68d43f25ff714300a375246bf0e91027e729bfb08ca8731101938959104d8e0f7ee3434589669abfce40ab0cf3e0333171570d6f491543b2eaa26b0db8efe70556998e785418e2b25b418a3e963fcf6e746ae2ee8f074b8b4a42b056e4a75c0ab44530cb4026b1ab52db74b2957434781b4ac38beeb5a259e89866056b5b63d50b3f6668a466da86c7cda1b2277c131d7b144b8d07510ae98dcb94cedbfe42ec30fada16bc55ee29e8ad841ec1cc8cab0c3383f3d236d5264c1d4221687d4023e3e93085c02e95b2f28f04770bcfdb05d798f11147701f00b96588e0b913bd5ccf1253095f8960fd9422505220ad185705c831bd66832f8a6ced6eb69fd6fbabd3265bcadf7a7768b76f24909c292724eb6983739900eae5f42c60846803cc2251c49012947d8a24ad8e726e386b3384489537127533f400ac9c25f4f050aee129830822b9d78f9f363b6444636845ceaa3739b37602d8665478293d8562821ca3a9ba305648b06ccbc2ed5fc37ea6f1987651090e79193f0f37d4735149990e5cf9c2a692a7b804788fe442e466b304c502f55ecfb542717ef4718cf1f89a103d40432a7987951082de2d101f37065ae3f11505615b515625e34716e171515da540566088902c6db6ac63fa02a544ad7cabbb927ce26f1f3444fb24b211e7a1676a7b9d011e4b27001007480ba7f4d2e6ef8ecb542d3fb02052ab7b105fe0dee12b56efaa46760c32092215aa26317a172809b8c62560f5586218a0cef064d808596b6dad7b604998901dabe4509c00ac3309567685cb8730bac92b713309fff9145b0a93375ad89967775be9c224097cffbb4432f0cd13e943678214e562f514a9730a43b01f7a6446fc5727ba7231db754230ccd2c002f5d48a27d0662255d50a264e35754708ef9656b92322f74a9c6d02943e387e6763d43c513618fb43c3f65951c490a014286778b85d277b061e44f07b3138262cb3586314ff7acd71384a5d028b92574407ce1d190aeb4aab64520279f22abbe0bb74c049ed2d7952bde587c7462a6b2d2063cd8ba1d3af302d35814375940ce1491c26b95eafd3e77fbd5d5430faa9855939d92144321061357c179241f90524fa7354bba330f561143c2086c8a826a37b7a5930a0624e4248cee2b4f2bd6f5e002ddbd76917d569750aa426d5e4a5cb1ce322c012c51e766f3ad172b9f885927034f6e9495c632e31022a37094875629828c36862ff2579cb38f4b5085b3b74dfed62d707545ce86be83c0103a6f0a9f31582a914bc50ff9e3a4165e18d63405df68a59ecd52d9d14a3aa5e6b7cc8aa20409531256ff75e94bb840ed0187d5b8626a8038c5a346cd93ad61d47eed18f109669260f4041dc979eb4dc8afc9a900b2dfdf60eb8ee08336c80c77ed5513c68"
	maddr, err := abeutil.DecodeMasterAddressAbe(maddrStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	derivedaddr := make([]abeutil.DerivedAddress, 3)
	for i := 0; i < 3; i++ {
		derivedaddr[i], err = maddr.GenerateDerivedAddress()
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	addrScripts := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		addrScripts[i] = append([]byte{0x00}, derivedaddr[i].Serialize()...)
	}
	fmt.Printf("Length of addr script is %d,%d,%d\n", len(addrScripts[0]), len(addrScripts[1]), len(addrScripts[2]))
	coinbaseTx := wire.MsgTxAbe{
		Version: 1,
		TxIns: []*wire.TxInAbe{
			{
				SerialNumber: chainhash.ZeroHash,
				PreviousOutPointRing: wire.OutPointRing{
					BlockHashs: []*chainhash.Hash{
						&chainhash.ZeroHash,
						{
							0x48, 0x68, 0x46,
						}, //this value can be covered by any value as a nonce of coinbase
						{
							/*This is the first block of abe*/
							0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
							0x68, 0x65, 0x20, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
							0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x6f, 0x66, 0x20,
							0x61, 0x62, 0x65,
						}, //this value can be any value
					},
					OutPoints: []*wire.OutPointAbe{
						{
							TxHash: chainhash.ZeroHash, // empty hash value
							Index:  0,                  // the index will be limited in a special range
						},
					},
				},
			},
		},
		TxOuts: []*wire.TxOutAbe{
			{
				ValueScript:   5000000000, // the initial value of coinbase transaction
				AddressScript: addrScripts[0],
			},
			{
				ValueScript:   100000000, // the initial value of coinbase transaction
				AddressScript: addrScripts[1],
			},
			{
				ValueScript:   20000000, // the initial value of coinbase transaction
				AddressScript: addrScripts[2],
			},
		},
		TxFee: 0,
		TxWitness: &wire.TxWitnessAbe{ //len(TxWitness.Witnesses)==0
			Witnesses: []wire.Witness{},
		},
	}
	for i := 0; i < 3; i++ {
		fmt.Printf("addrscript[%d]:\n", i)
		for j := 0; j < len(addrScripts[i]); j++ {
			fmt.Printf("%#.2x, ", addrScripts[i][j])
		}
		fmt.Println()
	}
	genesisMerkleRoot := coinbaseTx.TxHash()
	fmt.Println("coinbase tx hash:")
	for i := 0; i < len(genesisMerkleRoot); i++ {
		fmt.Printf("%#.2x, ", genesisMerkleRoot[i])
	}
	fmt.Println()
	currentTime := time.Now()
	fmt.Println("Time:")
	fmt.Printf("%#x", currentTime.Unix())
	fmt.Println()
	genesisBlock := wire.MsgBlockAbe{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  chainhash.Hash{},
			MerkleRoot: genesisMerkleRoot,
			Timestamp:  currentTime,
			Bits:       0x1e01ffff,
			Nonce:      0,
		},
		Transactions: []*wire.MsgTxAbe{&coinbaseTx},
	}
	for i := uint32(0); i <= ^uint32(0); i++ {
		genesisBlock.Header.Nonce = i
		hash := genesisBlock.Header.BlockHash()
		targetDifficulty := blockchain.CompactToBig(genesisBlock.Header.Bits)
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			fmt.Println("Successful!")
			fmt.Println("genesis block hash:")
			for i := 0; i < len(hash); i++ {
				fmt.Printf("%#.2x, ", hash[i])
			}
			fmt.Println()
			fmt.Println("Nonce:")
			fmt.Printf("%#x", genesisBlock.Header.Nonce)
			return
		}
	}
	return
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
