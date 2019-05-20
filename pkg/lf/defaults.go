/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package lf

// This contains the defaults for the Sol LF network, the global shared LF
// database for Earth and its neighbors in the Sol system. It should be good
// up to Kardashev type II civilization scale.

// SolDefaultNodeURLs is the default URL for clients to access Sol (servers operated by ZeroTier, Inc.)
var SolDefaultNodeURLs = []string{"https://lf.zerotier.com/"}

// SolGenesisRecords are the genesis records for initializing a Sol member node.
var SolGenesisRecords = []byte{0x1, 0x1, 0x92, 0x9, 0x63, 0xa9, 0x3b, 0xe3, 0x9b, 0xf8, 0xec, 0xfa, 0x1b, 0xf3, 0xc4, 0x85, 0xb9, 0x18, 0xa0, 0xb9, 0x1e, 0x74, 0xb4, 0x31, 0x4c, 0x75, 0x3e, 0x92, 0x5f, 0x2e, 0xfe, 0x91, 0xed, 0xe2, 0x2, 0x94, 0x13, 0x3b, 0x6b, 0xa5, 0x1c, 0x54, 0x47, 0x80, 0x30, 0xea, 0xce, 0x72, 0xc2, 0xad, 0x88, 0x6, 0x9f, 0x1e, 0xd5, 0xd0, 0xdd, 0xae, 0x5a, 0x34, 0x3a, 0xd7, 0xaa, 0x2, 0x8d, 0x86, 0x4e, 0x23, 0xd7, 0xe4, 0xb9, 0x53, 0xcd, 0x28, 0xe3, 0xd0, 0xd5, 0x6f, 0x59, 0xc9, 0x60, 0x1, 0x10, 0x65, 0xf5, 0xfc, 0xf4, 0xbe, 0xda, 0xdd, 0xad, 0xc3, 0x85, 0x69, 0x55, 0x9f, 0x5, 0xb0, 0xb3, 0x5c, 0x19, 0x8a, 0xfe, 0x1d, 0x32, 0xb2, 0xfc, 0x20, 0x19, 0xdd, 0xa5, 0xb7, 0xce, 0x50, 0x41, 0xd8, 0xfc, 0xca, 0x68, 0x6f, 0x3b, 0xd0, 0xa8, 0x39, 0x8b, 0xb9, 0x60, 0x36, 0x21, 0xad, 0x46, 0x4c, 0xa1, 0x85, 0xd7, 0xe8, 0xfc, 0xf8, 0xc4, 0x44, 0x17, 0x5, 0x20, 0x8c, 0xcc, 0x33, 0x6, 0x5b, 0x8e, 0x3d, 0x56, 0xf7, 0xfa, 0xd5, 0xc9, 0xb4, 0x58, 0xbf, 0x73, 0x8, 0x75, 0x69, 0x59, 0xf5, 0x8, 0x82, 0xd3, 0xee, 0x1e, 0xad, 0x91, 0xbb, 0x65, 0x13, 0x36, 0x15, 0x4e, 0xc8, 0x8f, 0xe8, 0x49, 0x85, 0x25, 0x9b, 0x4a, 0x76, 0x65, 0x4f, 0xad, 0xfa, 0x54, 0x5, 0xb4, 0x7f, 0x8d, 0x85, 0xfb, 0xca, 0x3d, 0x39, 0xb9, 0x7c, 0xb3, 0x7a, 0x6a, 0x2e, 0x1, 0x20, 0x32, 0x82, 0x29, 0xb7, 0xc2, 0x67, 0x18, 0x8d, 0xbb, 0x37, 0xc8, 0xea, 0x71, 0x71, 0x6f, 0x55, 0xb3, 0x56, 0x13, 0x50, 0x93, 0x6f, 0x2, 0x30, 0xe3, 0x2d, 0x61, 0x98, 0xd8, 0x35, 0x49, 0x42, 0x56, 0x51, 0x7c, 0x69, 0x90, 0xa4, 0x2c, 0x62, 0x42, 0x24, 0x6f, 0x36, 0xc7, 0xdd, 0x99, 0xb2, 0x35, 0x39, 0xad, 0x83, 0x29, 0x90, 0x25, 0xb1, 0xd8, 0xf3, 0xb3, 0x3, 0x5e, 0xa9, 0xd7, 0xb8, 0x51, 0x63, 0x6e, 0xef, 0x89, 0x49, 0xca, 0x19, 0x95, 0x8a, 0x31, 0xff, 0xda, 0x59, 0x3d, 0x4f, 0x50, 0x88, 0x7d, 0xc2, 0x6d, 0x41, 0xcf, 0x32, 0xaf, 0x9d, 0xa0, 0xe, 0xbd, 0xf2, 0xe, 0x89, 0xdf, 0xba, 0x26, 0xa8, 0x5f, 0x51, 0xe5, 0xbe, 0xf, 0x68, 0x19, 0x46, 0xa6, 0x2d, 0xcd, 0xfb, 0x28, 0x13, 0x2a, 0xd3, 0x3a, 0xae, 0xd5, 0x24, 0xb2, 0x9c, 0xb6, 0xa0, 0xc7, 0x41, 0x5c, 0x70, 0xf1, 0x22, 0x71, 0xd7, 0x4, 0x52, 0x5e, 0xf8, 0xc6, 0xbd, 0x27, 0xf3, 0x0, 0x16, 0x93, 0x8a, 0x8d, 0xd8, 0xe0, 0xe1, 0xd6, 0xf7, 0x45, 0x92, 0xfd, 0xe0, 0x62, 0x4a, 0xe0, 0x34, 0x19, 0xed, 0x7e, 0xc6, 0x81, 0x16, 0xf4, 0x54, 0xeb, 0xe6, 0xc9, 0x88, 0x16, 0xf8, 0xd8, 0x5e, 0xaf, 0xd7, 0xfd, 0xce, 0x7f, 0xea, 0x4a, 0xca, 0xec, 0x3e, 0xe0, 0xf9, 0x44, 0x86, 0xd, 0xa7, 0x71, 0x72, 0x81, 0x79, 0x1d, 0xc2, 0xe3, 0xbf, 0xd9, 0x6, 0x45, 0x1, 0xd3, 0xc3, 0xab, 0xa6, 0x96, 0x23, 0x5b, 0x36, 0x8e, 0x71, 0xa6, 0xb2, 0x5f, 0x5e, 0xb2, 0xb6, 0x3e, 0x25, 0x26, 0x87, 0x3c, 0x6c, 0xb1, 0x50, 0x52, 0xdc, 0xd1, 0x47, 0xca, 0x68, 0x9a, 0x93, 0xab, 0x43, 0x16, 0x40, 0x47, 0x7e, 0x5, 0x6b, 0xde, 0xf1, 0x40, 0xee, 0x77, 0x69, 0x6d, 0xa9, 0xaf, 0xf2, 0xde, 0x82, 0xf7, 0x8a, 0xee, 0x4c, 0x55, 0xc9, 0xa0, 0xfd, 0xa3, 0x83, 0x89, 0x43, 0x4b, 0x98, 0xd5, 0x7c, 0x69, 0xeb, 0x54, 0x12, 0x8c, 0x4a, 0x55, 0x40, 0x39, 0xe5, 0x7b, 0xa3, 0xa2, 0x92, 0x8b, 0x32, 0x41, 0xe3, 0x92, 0x3e, 0xad, 0x6f, 0xd9, 0x95, 0xb, 0xf3, 0xf, 0xc5, 0x1, 0xd4, 0xf0, 0x7b, 0x79, 0xdd, 0x84, 0x8, 0x78, 0x2b, 0x57, 0xff, 0x2f, 0x36, 0x65, 0xfc, 0xa6, 0x1a, 0xb3, 0xa3, 0x56, 0x83, 0x3c, 0xb9, 0xcd, 0x75, 0xdc, 0x20, 0xfa, 0x2f, 0x5d, 0xf3, 0x8d, 0xbe, 0xc0, 0x48, 0x42, 0x60, 0xa9, 0x89, 0x6c, 0x5f, 0x44, 0x44, 0x6, 0x51, 0x4f, 0x85, 0x9f, 0x24, 0xbe, 0xf6, 0xdc, 0x4f, 0x17, 0x22, 0xdf, 0x1e, 0xbc, 0x10, 0xa3, 0x40, 0x23, 0x3, 0x22, 0x2c, 0x79, 0x65, 0x3, 0xb8, 0xec, 0xc1, 0x1c, 0x75, 0x8, 0x25, 0x5f, 0x51, 0x60, 0x64, 0xc7, 0xa6, 0x24, 0x25, 0xb6, 0x3d, 0x1e, 0xff, 0xb1, 0x82, 0x5d, 0x23, 0x47, 0xd6, 0x8f, 0xcc, 0xbe, 0xea, 0x8b, 0xc6, 0x29, 0xf, 0xec, 0xf9, 0xd1, 0xef, 0x41, 0xf8, 0x1a, 0x1, 0x97, 0x89, 0x65, 0x40, 0x82, 0xb8, 0x3, 0x64, 0x38, 0x8f, 0x42, 0x84, 0xd3, 0x5c, 0x5d, 0x6a, 0x1d, 0x8b, 0xc2, 0xea, 0x88, 0xd7, 0x7c, 0x42, 0x10, 0xed, 0xc3, 0x36, 0xcf, 0x82, 0x5e, 0xd2, 0xcf, 0xf1, 0xa7, 0x65, 0xfb, 0x97, 0xe3, 0x7b, 0x21, 0x79, 0x32, 0xd3, 0x7b, 0xc7, 0xf6, 0x8f, 0x25, 0x9, 0x8, 0x37, 0x2c, 0xff, 0xe4, 0xee, 0xe7, 0x1, 0xcc, 0xea, 0x24, 0xa3, 0x33, 0xb5, 0xdd, 0xf5, 0x90, 0x27, 0xda, 0x2b, 0xdc, 0xe3, 0x7f, 0xa6, 0x14, 0x24, 0xa1, 0xfa, 0x9, 0x5b, 0xf7, 0x7c, 0x1c, 0x7c, 0xe1, 0x3, 0xbe, 0xb3, 0x26, 0xd1, 0xe9, 0xaa, 0xd9, 0xff, 0x4f, 0xa7, 0xa6, 0xae, 0x1d, 0x8d, 0x50, 0x60, 0x6, 0x7d, 0xdc, 0x5a, 0x2, 0x79, 0x9f, 0xdf, 0x70, 0xad, 0x87, 0xda, 0xb1, 0x35, 0xb4, 0xaf, 0x22, 0x43, 0x6, 0x37, 0x68, 0x3b, 0x81, 0x34, 0xab, 0xae, 0x8c, 0x8, 0x1e, 0xe4, 0xf7, 0x15, 0x4b, 0xad, 0x15, 0x67, 0x28, 0xd1, 0xea, 0xc4, 0xa3, 0x48, 0xa5, 0xd, 0xa8, 0xf4, 0x4f, 0x40, 0x3c, 0xf9, 0xf7, 0xfe, 0x73, 0x19, 0xa3, 0x11, 0xdd, 0x3, 0xfa, 0xa9, 0xda, 0xe3, 0xa0, 0x85, 0x85, 0xee, 0x4d, 0x76, 0xa0, 0xb5, 0x29, 0xfe, 0x44, 0x76, 0x71, 0xd5, 0xd7, 0x5f, 0x9d, 0x75, 0xf3, 0xa7, 0xbf, 0x4e, 0x62, 0xf1, 0xbb, 0xad, 0x61, 0x63, 0xd, 0xd1, 0x95, 0x67, 0xb0, 0x34, 0x3b, 0x39, 0xae, 0x77, 0xa, 0x1e, 0xbd, 0x9a, 0xdc, 0x4d, 0x9d, 0x1a, 0x1f, 0xb3, 0xf5, 0xc0, 0x98, 0x50, 0xa6, 0xd1, 0x6, 0x95, 0x15, 0x94, 0x26, 0xd4, 0xf, 0xe, 0x61, 0x53, 0x3f, 0x20, 0x7a, 0xf8, 0x39, 0x27, 0xf6, 0xae, 0x6a, 0x85, 0xc3, 0x3a, 0xfd, 0xd3, 0x4a, 0xc8, 0x96, 0xb4, 0x5d, 0xb2, 0x20, 0x18, 0x1b, 0x3a, 0x63, 0x19, 0xa6, 0xef, 0xca, 0xfd, 0x70, 0xa9, 0x45, 0x35, 0x69, 0xf6, 0x34, 0xf8, 0x67, 0xa2, 0xc9, 0x7d, 0xfc, 0xb7, 0x7, 0x8b, 0xca, 0x69, 0x80, 0x29, 0xcc, 0xec, 0x30, 0x25, 0x3, 0x60, 0x1b, 0xa7, 0x47, 0xec, 0xe6, 0xe5, 0x3, 0xe8, 0xff, 0x75, 0x2d, 0x5d, 0x1d, 0x4b, 0x28, 0x8e, 0xd9, 0x2f, 0x5, 0x86, 0x72, 0x7, 0x87, 0xec, 0xaa, 0xe5, 0xec, 0x4b, 0x5f, 0x54, 0x98, 0x64, 0x53, 0x84, 0x76, 0x6, 0x2a, 0x3c, 0xde, 0x3c, 0xf4, 0x9a, 0x49, 0x3f, 0x4d, 0xc2, 0x3e, 0xd7, 0x2, 0x19, 0xb5, 0xe3, 0xc3, 0x93, 0x9e, 0x6c, 0x81, 0xba, 0xa2, 0xb7, 0xe8, 0xeb, 0xab, 0xfc, 0x74, 0xfb, 0x31, 0x73, 0x46, 0x32, 0x9, 0x44, 0x6a, 0xf7, 0x7d, 0xc7, 0x7f, 0x39, 0xc2, 0x85, 0x6a, 0x9f, 0xe8, 0xc9, 0x6b, 0x1e, 0x75, 0xd5, 0x7e, 0xad, 0x6a, 0x17, 0x9e, 0x6f, 0xee, 0x21, 0xa4, 0xc6, 0x1d, 0xe0, 0x73, 0xd7, 0x81, 0x60, 0xf0, 0x95, 0xfa, 0xb, 0x46, 0x2f, 0xce, 0x74, 0xc4, 0xc2, 0xee, 0xbd, 0x6, 0x78, 0xe5, 0x8b, 0xc4, 0x70, 0xeb, 0xe, 0x90, 0xb9, 0x92, 0xbe, 0x5f, 0x41, 0x33, 0x84, 0xe3, 0xe3, 0x92, 0xf7, 0x2e, 0x43, 0x8, 0x1f, 0x80, 0x46, 0x72, 0x7b, 0xe7, 0x69, 0x48, 0x93, 0x26, 0x26, 0xa2, 0x77, 0x4e, 0x42, 0xa2, 0x92, 0xd9, 0x82, 0x86, 0xfe, 0x35, 0x9e, 0xc8, 0xd4, 0x94, 0x31, 0x65, 0xc5, 0xf6, 0x9e, 0xd5, 0x15, 0x79, 0xf7, 0x51, 0xdb, 0xc6, 0x15, 0x88, 0xbd, 0xc, 0x9e, 0xbf, 0xba, 0x2d, 0xf9, 0xc8, 0xc, 0xf2, 0x56, 0xdd, 0x5f, 0x3d, 0x5e, 0xe2, 0xe9, 0xc8, 0x36, 0xc4, 0x29, 0xf9, 0x13, 0xce, 0xdf, 0xb5, 0xa9, 0x20, 0x6e, 0x32, 0x5d, 0xbb, 0xc2, 0x47, 0xe9, 0x80, 0x75, 0x0, 0xc6, 0xcf, 0xcf, 0x43, 0x9f, 0xd, 0x1f, 0xd, 0xcb, 0x90, 0xf3, 0xf6, 0x81, 0xcd, 0xdb, 0x4e, 0xfa, 0xfc, 0x21, 0x11, 0xa4, 0x6e, 0xa9, 0x72, 0xff, 0xc4, 0x20, 0x37, 0x69, 0x46, 0x70, 0x99, 0xaf, 0xb3, 0xc8, 0x6a, 0xfa, 0x71, 0xad, 0x4f, 0x54, 0x8d, 0x75, 0xe, 0xf9, 0x76, 0xa9, 0x94, 0x7d, 0x60, 0x37, 0x36, 0x2e, 0xc2, 0x2f, 0xe7, 0x95, 0x18, 0x76, 0x1b, 0xab, 0xd3, 0x96, 0x48, 0x21, 0x22, 0x48, 0xd, 0x8a, 0x7c, 0xd6, 0x55, 0xe0, 0xf6, 0x57, 0x37, 0x17, 0x64, 0xee, 0x50, 0xd7, 0x18, 0x0, 0xc4, 0xe7, 0x8c, 0xe7, 0x5, 0x0, 0x1, 0xf, 0x60, 0x62, 0xe0, 0xd8, 0xf, 0x60, 0x53, 0xe5, 0xe3, 0x0, 0x9, 0x7c, 0xd4, 0x60, 0xa7, 0x33, 0x49, 0xd5, 0x84, 0xb8, 0xf3, 0x1d, 0x8d, 0xac, 0x15, 0x2c, 0xc7, 0xcf, 0x6d, 0x8d, 0xdd, 0xb4, 0x1b, 0xe9, 0x72, 0xfa, 0x52, 0x15, 0x38, 0xb8, 0xbc, 0x8b, 0x49, 0x5e, 0xa1, 0x75, 0xaf, 0x8c, 0xf9, 0x1, 0x69, 0xf, 0x55, 0x99, 0x54, 0x9e, 0xea, 0xad, 0xbf, 0x83, 0xf9, 0x7f, 0xe7, 0x36, 0x5a, 0x62, 0xbf, 0x4, 0x93, 0x6e, 0x46, 0xc8, 0x52, 0x7b, 0xd6, 0x90, 0x56, 0xdd, 0xe5, 0x8f, 0xc9, 0x3d, 0xb1, 0x8b, 0x34, 0x5a, 0xb6, 0xa8, 0xd, 0xf0, 0xec, 0x2b, 0xab, 0x68, 0x2d, 0x95, 0x91, 0x41, 0x2f, 0xa9, 0x64, 0xd, 0xd5, 0xd7, 0xd5, 0x34, 0x8, 0x81, 0xcd, 0xed, 0x1, 0x1, 0x0, 0x18, 0x76, 0x1b, 0xab, 0xd3, 0x96, 0x48, 0x21, 0x22, 0x48, 0xd, 0x8a, 0x7c, 0xd6, 0x55, 0xe0, 0xf6, 0x57, 0x37, 0x17, 0x64, 0xee, 0x50, 0xd7, 0x18, 0x1, 0x73, 0x72, 0x16, 0xa1, 0x3b, 0x2d, 0x97, 0xd6, 0xcd, 0xea, 0x58, 0x5e, 0xaf, 0x73, 0xf6, 0x6f, 0xde, 0x95, 0xef, 0xbe, 0x90, 0x4, 0xeb, 0xc2, 0x90, 0x72, 0xac, 0xe2, 0x50, 0x45, 0xbd, 0x98, 0xc5, 0xe7, 0x8c, 0xe7, 0x5, 0x0, 0x1, 0x86, 0xd, 0x27, 0x5, 0x9d, 0x81, 0x49, 0xcf, 0x23, 0xb2, 0x0, 0x0, 0x1a, 0x4c, 0x60, 0xd5, 0xcb, 0x88, 0x6a, 0xba, 0x45, 0x41, 0xd, 0xce, 0xa, 0xd3, 0x24, 0x54, 0x1e, 0xe0, 0xcb, 0xe9, 0xc4, 0x98, 0x3, 0x71, 0x81, 0xac, 0xd6, 0x89, 0xf9, 0x8a, 0xa1, 0x69, 0x79, 0xb4, 0xdb, 0xda, 0x88, 0xae, 0x2c, 0xa, 0xba, 0x48, 0xf4, 0x67, 0x32, 0x9c, 0x9b, 0x77, 0x7a, 0x39, 0xb7, 0x2d, 0x7d, 0x92, 0xd3, 0x95, 0x70, 0x74, 0x9e, 0xee, 0x10, 0x77, 0xa0, 0xd0, 0xfa, 0x14, 0x46, 0x64, 0x8, 0xd8, 0x41, 0x54, 0x2c, 0x68, 0x1b, 0xb0, 0xa8, 0xdb, 0x19, 0xc3, 0x4a, 0x34, 0x8f, 0x25, 0x10, 0x5c, 0x6c, 0x20, 0x8e, 0xd, 0x8, 0xf1, 0x37, 0xaa, 0x64, 0xb1, 0xaa, 0x85, 0xd8}
