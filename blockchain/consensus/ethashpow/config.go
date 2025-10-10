// Copyright (c) 2021-2025 The Abelian Foundation. All rights reserved.
// This file is part of Abelian.
//
// This source code is licensed under the MIT License found in the LICENSE file
// in the root directory of this source tree.
//
// Abelian Foundation 2021-2025

package ethashpow

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

func GetDefaultEthashConfigCopy() EthashConfig {
	config := EthashConfig{}

	config.CacheDir = defaultEthashCfg.CacheDir
	config.CachesInMem = defaultEthashCfg.CachesInMem
	config.CachesOnDisk = defaultEthashCfg.CachesOnDisk
	config.CachesLockMmap = defaultEthashCfg.CachesLockMmap
	config.DatasetsInMem = defaultEthashCfg.DatasetsInMem
	config.DatasetsOnDisk = defaultEthashCfg.DatasetsOnDisk
	config.DatasetsLockMmap = defaultEthashCfg.DatasetsLockMmap
	config.PowMode = defaultEthashCfg.PowMode
	config.VerifyByFullDAG = defaultEthashCfg.VerifyByFullDAG
	config.BlockHeightStart = defaultEthashCfg.BlockHeightStart
	config.EpochLength = defaultEthashCfg.EpochLength

	return config
}

// defaultEthashCfg contains default settings for AbelEthash.
var defaultEthashCfg = EthashConfig{
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

// init initialize the CacheDir and DatasetDir
func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "darwin" {
		defaultEthashCfg.DatasetDir = filepath.Join(home, "Library", "Ethash")
	} else if runtime.GOOS == "windows" {
		localappdata := os.Getenv("LOCALAPPDATA")
		if localappdata != "" {
			defaultEthashCfg.DatasetDir = filepath.Join(localappdata, "Ethash")
		} else {
			defaultEthashCfg.DatasetDir = filepath.Join(home, "AppData", "Local", "Ethash")
		}
	} else {
		defaultEthashCfg.DatasetDir = filepath.Join(home, ".ethash")
	}

	// set CacheDir to be the same as DatasetDir
	defaultEthashCfg.CacheDir = defaultEthashCfg.DatasetDir
}
