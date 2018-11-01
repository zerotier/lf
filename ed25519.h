/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#ifndef ZTLF_ED25519_H
#define ZTLF_ED25519_H

#define ZTLF_ED25519_PUBLIC_KEY_SIZE  32
#define ZTLF_ED25519_PRIVATE_KEY_SIZE 64
#define ZTLF_ED25519_SIGNATURE_SIZE   64

void ZTLF_ed25519CreateKeypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ZTLF_ed25519Sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int ZTLF_ed25519Verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);

#endif
