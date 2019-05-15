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

type ui32tree struct {
	p    *[]ui32tree
	l, r int
	v    uint32
}

func (tree *ui32tree) add(v uint32) *ui32tree {
	if tree.p == nil {
		pp := make([]ui32tree, 0, 65536)
		tree.p = &pp
		tree.v = v
		tree.l = -1
		tree.r = -1
	} else {
		if v < tree.v {
			if tree.l >= 0 {
				(*tree.p)[tree.l].add(v)
			} else {
				*tree.p = append(*tree.p, ui32tree{p: tree.p, l: -1, r: -1, v: v})
				tree.l = len(*tree.p) - 1
			}
		} else {
			if tree.r >= 0 {
				(*tree.p)[tree.r].add(v)
			} else {
				*tree.p = append(*tree.p, ui32tree{p: tree.p, l: -1, r: -1, v: v})
				tree.r = len(*tree.p) - 1
			}
		}
	}
	return tree
}

func (tree *ui32tree) sorted() []uint32 {
	var order []uint32
	if tree.l >= 0 {
		order = append(order, (*tree.p)[tree.l].sorted()...)
	}
	order = append(order, tree.v)
	if tree.r >= 0 {
		order = append(order, (*tree.p)[tree.r].sorted()...)
	}
	return order
}
