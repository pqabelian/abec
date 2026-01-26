// Copyright (c) 2021-2025 The Abelian Foundation. All rights reserved.
// This file is part of Abelian.
// Copyright (c) 2021-2025 The Abelian Foundation. All rights reserved.
// This file is part of Abelian.
//
// This source code is licensed under the MIT License found in the LICENSE file
// in the root directory of this source tree.
//
// This file includes code from btcd, which is licensed under the ISC License.
// See the NOTICE file for more details.
//
// Abelian Foundation 2021-2025
//
// Original btcd copyright notice:

// Copyright (c) 2021 The Abelian Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//

package ethashpow

import "github.com/pqabelian/abec/abelog"

// log is a logger that is initialized with no output filters.
// This means the package will not perform any logging by default until the caller requests it.
var log abelog.Logger

// The default amount of logging is none.
func init() {
	DisableLog()
}

// DisableLog disables all library log output.
// Logging output is disabled by default until UseLogger is called.
func DisableLog() {
	log = abelog.Disabled
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger abelog.Logger) {
	log = logger
}
