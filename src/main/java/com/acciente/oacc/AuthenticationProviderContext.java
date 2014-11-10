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
 * An instance of this interface is passed to the {@link AuthenticationProvider#setContext(AuthenticationProviderContext)}.
 * This interface is used to provide a custom {@link AuthenticationProvider} implementation access to context information
 * such as the built-in {@link AuthenticationProvider}. The built-in {@link AuthenticationProvider} can be used by a
 * custom {@link AuthenticationProvider} if it desires to delegate to built-in {@link AuthenticationProvider} cases
 * that it does not need to handle with custom logic.
 *
 */
public interface AuthenticationProviderContext {
   /**
    * Provides access to the built-in {@link AuthenticationProvider} implementation.
    * @return the built-in {@link AuthenticationProvider} implementation.
    */
   AuthenticationProvider getBuiltInAuthenticationProvider();
}
