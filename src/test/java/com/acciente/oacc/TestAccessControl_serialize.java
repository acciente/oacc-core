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

import com.acciente.oacc.helper.TestConfigLoader;
import com.acciente.oacc.sql.internal.SQLAccessControlContext;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.fail;

public class TestAccessControl_serialize extends TestAccessControlBase {
   @Test
   public void serialize_serialization_shouldSucceed() throws IOException {
      ObjectOutputStream objectOutputStream = null;
      try {
         objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());
         objectOutputStream.writeObject(accessControlContext);
      }
      finally {
         if (objectOutputStream != null) {
            objectOutputStream.close();
         }
      }
   }

   @Test
   public void serialize_deserializationWithoutPostDeserialize_shouldFail() throws IOException, ClassNotFoundException {
      Resource systemAuthResource = getSystemResource();
      accessControlContext.authenticate(systemAuthResource,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      Assert.assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));

      if (accessControlContext instanceof SQLAccessControlContext) {
         ByteArrayOutputStream byteArrayOutputStream = null;
         ObjectOutputStream objectOutputStream = null;
         ObjectInputStream objectInputStream = null;
         AccessControlContext deserializedAccessControlContext;

         try {
            // serialize into byte array
            byteArrayOutputStream = new ByteArrayOutputStream();
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(accessControlContext);
            objectOutputStream.close();
            final byte[] serializedAccessControlContext = byteArrayOutputStream.toByteArray();

            // deserialize from byte array
            objectInputStream = new ObjectInputStream(new ByteArrayInputStream(serializedAccessControlContext));
            deserializedAccessControlContext = (AccessControlContext) objectInputStream.readObject();
         }
         finally {
            if (byteArrayOutputStream != null) {
               byteArrayOutputStream.close();
            }
            if (objectOutputStream != null) {
               objectOutputStream.close();
            }
            if (objectInputStream != null) {
               objectOutputStream.close();
            }
         }

         // currently we don't check that accessControlContext is initialized within *every* method, so
         // the following will succeed because it only deals with a field that was serializable by default
         deserializedAccessControlContext.getAuthenticatedResource();

         // attempt to use deserialized AccessControlContext without calling initialize()
         try {
            deserializedAccessControlContext.authenticate(systemAuthResource,
                                                          PasswordCredentials.newInstance(TestConfigLoader
                                                                                                .getOaccRootPassword()));
            fail("using deserialized AccessControlContext without re-initialization should have failed");
         }
         catch (IllegalStateException e) {
             Assert.assertThat(e.getMessage().toLowerCase(), containsString("not initialized"));
         }

         final String domainName = generateUniqueDomainName();
         try {
            deserializedAccessControlContext.createDomain(domainName);
            fail("using deserialized AccessControlContext without re-initialization should have failed");
         }
         catch (IllegalStateException e) {
             Assert.assertThat(e.getMessage().toLowerCase(), containsString("not initialized"));
         }

         final String resourceClassName = generateUniqueResourceClassName();
         try {
            deserializedAccessControlContext.createResourceClass(resourceClassName, false, true);
            fail("using deserialized AccessControlContext without re-initialization should have failed");
         }
         catch (IllegalStateException e) {
             Assert.assertThat(e.getMessage().toLowerCase(), containsString("not initialized"));
         }

         try {
            deserializedAccessControlContext.createResource(resourceClassName, domainName);
            fail("using deserialized AccessControlContext without re-initialization should have failed");
         }
         catch (IllegalStateException e) {
             Assert.assertThat(e.getMessage().toLowerCase(), containsString("not initialized"));
         }
      }
   }

   @Test
   public void serialize_deserializationWithPostDeserialize_shouldSucceed() throws IOException, ClassNotFoundException {
      Resource systemAuthResource = getSystemResource();
      accessControlContext.authenticate(systemAuthResource,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      Assert.assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));

      if (accessControlContext instanceof SQLAccessControlContext) {
         ByteArrayOutputStream byteArrayOutputStream = null;
         ObjectOutputStream objectOutputStream = null;
         ObjectInputStream objectInputStream = null;
         AccessControlContext deserializedAccessControlContext;

         try {
            // serialize into byte array
            byteArrayOutputStream = new ByteArrayOutputStream();
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(accessControlContext);
            objectOutputStream.close();
            final byte[] serializedAccessControlContext = byteArrayOutputStream.toByteArray();

            // deserialize from byte array
            objectInputStream = new ObjectInputStream(new ByteArrayInputStream(serializedAccessControlContext));
            deserializedAccessControlContext = (AccessControlContext) objectInputStream.readObject();
         }
         finally {
            if (byteArrayOutputStream != null) {
               byteArrayOutputStream.close();
            }
            if (objectOutputStream != null) {
               objectOutputStream.close();
            }
            if (objectInputStream != null) {
               objectOutputStream.close();
            }
         }

         // call initialize()
         SQLAccessControlContext.postDeserialize(deserializedAccessControlContext, TestConfigLoader.getDataSource());

         // verify state hasn't changed
         Assert.assertThat(deserializedAccessControlContext.getAuthenticatedResource(), is(systemAuthResource));

         // verify it's still usable
         final String domainName = generateUniqueDomainName();
         deserializedAccessControlContext.createDomain(domainName);

         final String resourceClassName = generateUniqueResourceClassName();
         deserializedAccessControlContext.createResourceClass(resourceClassName, false, true);

         final Resource resource = deserializedAccessControlContext.createResource(resourceClassName, domainName);

         final ResourceClassInfo resourceClassInfo = deserializedAccessControlContext.getResourceClassInfoByResource(resource);
         Assert.assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));

         deserializedAccessControlContext.authenticate(systemAuthResource,
                                                       PasswordCredentials.newInstance(TestConfigLoader
                                                                                             .getOaccRootPassword()));
      }
   }
}
