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

import com.acciente.oacc.helper.TestConfigLoader;
import com.acciente.oacc.sql.internal.SQLAccessControlContext;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.fail;

public class TestAccessControl_serialize extends TestAccessControlBase {
   @Test
   public void serialize_withoutPreSerialization_shouldFail() throws IOException {
      ObjectOutputStream objectOutputStream = null;
      try {
         objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());
         objectOutputStream.writeObject(accessControlContext);
         fail("serializing accessControlContext instance without calling preSerialize() should have failed");
      }
      catch (NotSerializableException e)
      {
         // ignore - this is the expected exception
      }
      finally {
         if (objectOutputStream != null) {
            objectOutputStream.close();
         }
      }
   }

   @Test
   public void serialize_withPreSerialization_shouldSucceed() throws IOException, ClassNotFoundException {
      Resource systemAuthResource = getSystemResource();
      accessControlContext.authenticate(systemAuthResource,
                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
      Assert.assertThat(accessControlContext.getAuthenticatedResource(), is(systemAuthResource));

      if (accessControlContext instanceof SQLAccessControlContext) {
         ByteArrayOutputStream byteArrayOutputStream = null;
         ObjectOutputStream objectOutputStream = null;
         ObjectInputStream objectInputStream = null;
         AccessControlContext deserializedAccessControlContext;

         // call preSerialize()
         SQLAccessControlContext.preSerialize(accessControlContext);

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

         // call postDeserialize()
         SQLAccessControlContext.postDeserialize(deserializedAccessControlContext, TestConfigLoader.getDataSource());

         // verify state hasn't changed
         Assert.assertThat(deserializedAccessControlContext.getAuthenticatedResource(), is(systemAuthResource));

         // verify it's still usable
         deserializedAccessControlContext.authenticate(systemAuthResource,
                                                       PasswordCredentials.newInstance(TestConfigLoader
                                                                                             .getOaccRootPassword()));
      }
   }
}
