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
package com.acciente.oacc.encryptor.jasypt;

import org.jasypt.digest.StandardByteDigester;
import org.junit.Test;

import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.IsSame.sameInstance;
import static org.junit.Assert.assertThat;

public class StandardByteDigesterPoolTest {
   private final StandardByteDigesterPool pool = new StandardByteDigesterPool();

   @Test
   public void testSameInstanceReturned() throws Exception {
      final StandardByteDigester digester_1 = pool.getStandardByteDigester("SHA-256", 1000, 16);
      final StandardByteDigester digester_2 = pool.getStandardByteDigester("SHA-256", 1000, 16);

      assertThat(digester_1, not(nullValue()));
      assertThat(digester_2, not(nullValue()));
      assertThat(digester_2, sameInstance(digester_1));
   }

   @Test
   public void testDifferentInstanceReturned() throws Exception {
      final StandardByteDigester digester_1 = pool.getStandardByteDigester("SHA-256", 1000, 16);
      final StandardByteDigester digester_2 = pool.getStandardByteDigester("SHA-256", 2000, 16);

      assertThat(digester_1, not(nullValue()));
      assertThat(digester_2, not(nullValue()));
      assertThat(digester_2, not(sameInstance(digester_1)));
   }

   @Test
   public void testDifferentInstanceThenSameInstanceReturned() throws Exception {
      final StandardByteDigester digester_1 = pool.getStandardByteDigester("SHA-256", 1000, 16);
      final StandardByteDigester digester_2 = pool.getStandardByteDigester("SHA-256", 2000, 16);
      final StandardByteDigester digester_3 = pool.getStandardByteDigester("SHA-256", 1000, 16);
      final StandardByteDigester digester_4 = pool.getStandardByteDigester("SHA-256", 2000, 16);

      assertThat(digester_1, not(nullValue()));
      assertThat(digester_2, not(nullValue()));
      assertThat(digester_3, not(nullValue()));
      assertThat(digester_4, not(nullValue()));

      assertThat(digester_2, not(sameInstance(digester_1)));
      assertThat(digester_3, sameInstance(digester_1));
      assertThat(digester_4, sameInstance(digester_2));
   }
}