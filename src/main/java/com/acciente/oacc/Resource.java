/*
 * Copyright 2009-2015, Acciente LLC
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
 * A resource is the abstraction for an application object. A resource is created and
 * associated with every object in the application that needs to have access control.
 * All security relationships for the application object are defined using the using
 * its corresponding resource.
 *
 * To create a new resource use  {@link AccessControlContext#createResource(String)}
 * or one of its variants in {@link AccessControlContext}.
 *
 * To create a Resource instance using a previously persisted resource id use the
 * factory method {@link Resources#getInstance(long)}.
 */
public interface Resource {
   /**
    * @return The id of this resource. This id is typically persisted as an attribute
    * of the application object that it is associated with.
    */
   long getId();
}
