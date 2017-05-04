/*
 * Copyright 2009-2017, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc.encryptor;

import com.acciente.oacc.encryptor.bcrypt.BCryptPasswordEncryptor;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;
import com.acciente.oacc.sql.internal.SQLPasswordAuthenticationProvider;

/**
 * This interface is used to configure the password encryption scheme employed
 * by the built-in {@link SQLPasswordAuthenticationProvider}.
 * The goal is to enable using different password encryption algorithms with
 * the built-in authentication provider.
 * <p>
 * In OACC v2.0.0-rc.7 and prior the built-in authentication provider always used
 * Jasypt internally and did not allow other options. Now there are factory methods
 * in {@link SQLAccessControlContextFactory} to specify the PasswordEncryptor to be
 * used in the built-in authentication provider.
 * <p>
 * The following password encryptor implementations are provided:
 * <ul>
 * <li>{@link JasyptPasswordEncryptor} - hashes passwords using a Jasypt digester.
 *    The following static factory method provides different configuration options:
 *    <ul>
 *    <li>{@link JasyptPasswordEncryptor#newInstance(String algorithm, int iterations, int saltSizeBytes)}</li>
 *    </ul>
 *    Compatibility notes:<br>
 *    The new JasyptPasswordEncryptor implementation writes a header prefix to the
 *    password hashes that it creates, and is not compatible with the
 *    {@link com.acciente.oacc.encryptor.jasypt.LegacyJasyptPasswordEncryptor
 *    LegacyJasyptPasswordEncryptor} used in OACC v2.0.0-rc.7 or before.
 * </li>
 * <li>{@link BCryptPasswordEncryptor} - hashes passwords using an OpenBSD BCrypt implementation.
 *    The following static factory methods provide different configuration options:
 *    <ul>
 *    <li>{@link BCryptPasswordEncryptor#newInstance(int costFactor)}</li>
 *    <li>{@link BCryptPasswordEncryptor#newInstance(int minComputedCostFactor, int minComputeDurationInMillis)}</li>
 *    </ul>
 * </li>
 * <li>{@link TransitioningPasswordEncryptor} - provides a means to transition from
 *    an existing encryption scheme to a new one in an environment where OACC was
 *    already deployed, i.e. where existing passwords in the tables were encrypted
 *    with a different or older password encryptor. The following factory method
 *    provides the configuration options:
 *    <ul>
 *    <li>{@link TransitioningPasswordEncryptor#newInstance(PasswordEncryptor new, PasswordEncryptor old)}</li>
 *    </ul>
 * </li>
 * </ul>
 */
public interface PasswordEncryptor {
   /**
    * Encrypts a password.
    *
    * @param password the plaintext password as a cleanable char[]
    * @return the BASE-64 digest of encrypting the specified password
    */
   String encryptPassword(char[] password);


   /**
    * Checks an unencrypted password against an encrypted one to see if they match.
    *
    * @param plainPassword     the plaintext password as a cleanable char[]
    * @param encryptedPassword the (BASE-64) digest from an earlier encryption against which to check the plaintext password
    * @return true if passwords match, false otherwise
    */
   boolean checkPassword(char[] plainPassword,
                         String encryptedPassword);

}
