package ethash

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// DefaultCfg contains default settings for abelethash.
var DefaultCfg = Config{
	CacheDir:         "ethash",
	CachesInMem:      1, // 2,
	CachesOnDisk:     3,
	CachesLockMmap:   false,
	DatasetsInMem:    1,
	DatasetsOnDisk:   3, // to support rollback of the chain, which may cause the epoch change, we store 3 datasets on disk.
	DatasetsLockMmap: false,

	PowMode:          ModeNormal,
	VerifyByFullDAG:  false, //	only when mining and is specified explicitly, it could be true.
	BlockHeightStart: 0,
	EpochLength:      4000,
}

//	init() initialize the CacheDir and DatasetDir
func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "darwin" {
		DefaultCfg.DatasetDir = filepath.Join(home, "Library", "Ethash")
	} else if runtime.GOOS == "windows" {
		localappdata := os.Getenv("LOCALAPPDATA")
		if localappdata != "" {
			DefaultCfg.DatasetDir = filepath.Join(localappdata, "Ethash")
		} else {
			DefaultCfg.DatasetDir = filepath.Join(home, "AppData", "Local", "Ethash")
		}
	} else {
		DefaultCfg.DatasetDir = filepath.Join(home, ".ethash")
	}

	// set CacheDir to be the same as DatasetDir
	DefaultCfg.CacheDir = DefaultCfg.DatasetDir
}
