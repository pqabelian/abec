// Copyright (c) 2020 The Abelian Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package connmgr implements a generic Bitcoin network connection manager.

Connection Manager Overview

Connection Manager handles all the general connection concerns such as
maintaining a set number of outbound connections, sourcing peers, banning,
limiting max connections, tor lookup, etc.
*/

package connmgr
