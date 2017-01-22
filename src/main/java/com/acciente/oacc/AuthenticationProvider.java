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
package com.acciente.oacc;

/**
 * Provides the mechanism to authenticate a resource based on specified credentials and to update those credentials.
 * <p/>
 * An application can provide an implementation of this interface to provide a custom authentication
 * mechanism for resources. Such a custom authentication provider is free to use password, biometric or
 * any other means for authentication.
 */
public interface AuthenticationProvider {
   /**
    * Authenticates the specified resource using the supplied credentials.
    *
    * @param resource the resource to be authenticated
    * @param credentials the credentials to authenticate the resource
    * @throws com.acciente.oacc.IncorrectCredentialsException if authentication failed due to incorrect credentials
    */
   void authenticate(Resource resource, Credentials credentials);

   /**
    * Verifies that the specified resource is authenticated.
    * <p/>
    * The authentication provider implementation should throw a NotAuthenticatedException if the
    * specified resource is currently NOT authenticated, or should throw an UnsupportedOperationException
    * if it does not support reporting of the authentication status without credentials.
    *
    * @param resource the resource to be authenticated
    */
   void authenticate(Resource resource);

   /**
    * Checks if the the authentication credentials are valid for the specified resource class and domain.
    * <p/>
    * This method may check if the credentials satisfy the minimum strength requirements, for example.
    *
    * @param resourceClassName the resource class for which to validate the specified credentials
    * @param domainName the domain for which to validate the specified credentials
    * @param credentials the authentication credentials to validate
    * @throws com.acciente.oacc.InvalidCredentialsException if the credentials are invalid
    */
   void validateCredentials(String resourceClassName, String domainName, Credentials credentials);

   /**
    * Sets (or resets) the authentication credentials of the specified resource.
    *
    * @param resource the resource for which the credentials should be set
    * @param credentials the new authentication credentials for the resource
    */
   void setCredentials(Resource resource, Credentials credentials);

   /**
    * Removes the authentication credentials of the specified resource.
    *
    * @param resource the resource for which the credentials should be removed
    */
   void deleteCredentials(Resource resource);
}
