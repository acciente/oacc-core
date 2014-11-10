/*
 * Copyright 2009-2014, Acciente LLC
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
package com.acciente.oacc;

/**
 * An application can provide an implementation of this interface to provide a custom authentication
 * mechanism. Such a custom authentication provider is free to use password, biometric or any other means
 * for authentication.
 */
public interface AuthenticationProvider {
   /**
    * This method is called to provide a custom {@link AuthenticationProvider} implementation access to the
    * built-in authentication provider.
    *
    * @param context an instance of {@link AuthenticationProviderContext}
    * @throws AccessControlException if the implementation decides that an unrecoverable error has occurred.
    */
   void setContext(AuthenticationProviderContext context) throws AccessControlException;

   /**
    * This method is called to request authentication using the supplied credentials.
    *
    * @param credentials the credentials of the resource requesting authentication.
    * @throws AccessControlException
    */
   void authenticate(Credentials credentials) throws AccessControlException;

   /**
    * This method is called to request updating authentication credentials.
    *
    * @param credentials the new authentication credentials
    * @throws AccessControlException if currently authenticated resource does not have permission to update
    * the credentials or another error occurs.
    */
   void updateCredentials(Credentials credentials) throws AccessControlException;
}
