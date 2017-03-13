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

import com.ibm.icu.text.Normalizer2;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ICU4JDestBufferWorstCaseExpansionTest {
   private Normalizer2 normalizer;
   private String src;
   private StringBuilder dest;

   @Before
   public void setUp() throws Exception {
      normalizer = Normalizer2.getNFCInstance();
      dest = new StringBuilder(0);
      assertEquals(0, dest.capacity());
   }

   @Test
   public void testCharSeq_foobar() throws Exception {
      src="foobar";
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(6, dest.capacity());
      assertEquals(6, dest.length());
   }

   @Test
   public void testChar_Ufb2c() throws Exception {
      src="\ufb2c";
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(6, dest.capacity());
      assertEquals(3, dest.length());
   }

   @Test
   public void testChar_Ufb2cX2() throws Exception {
      src="xx".replace("x", "\ufb2c");
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(6, dest.capacity());
      assertEquals(6, dest.length());
   }

   @Test
   public void testChar_Ufb2cX3() throws Exception {
      src="xxx".replace("x", "\ufb2c");
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(18, dest.capacity());
      assertEquals(9, dest.length());
   }

   @Test
   public void testChar_Ufb2cX4() throws Exception {
      src="xxxx".replace("x", "\ufb2c");
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(22, dest.capacity());
      assertEquals(12, dest.length());
   }

   @Test
   public void testChar_U1f82() throws Exception {
      src="\u1f82";
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(2, dest.capacity());
      assertEquals(1, dest.length());
   }


   @Test
   public void testChar_Ufdfa() throws Exception {
      src="\ufdfa";
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(2, dest.capacity());
      assertEquals(1, dest.length());
   }

   @Test
   public void testCharSeq_Ufb2c_U1f82() throws Exception {
      src="\ufb2c\u1f82";
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(6, dest.capacity());
      assertEquals(4, dest.length());
   }

   @Test
   public void testCharSeq_Ufb2c_U1f82_Ufdfa() throws Exception {
      src="\ufb2c\u1f82\ufdfa";
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(8, dest.capacity());
      assertEquals(5, dest.length());
   }

   @Test
   public void testCharSeq_Ufb2c_U1f82_UfdfaX2() throws Exception {
      src="xx".replace("x", "\ufb2c\u1f82\ufdfa");
      normalizer.normalize(src, dest);
      printStats();
      assertEquals(14, dest.capacity());
      assertEquals(10, dest.length());
   }

   private void printStats() {
      System.out.printf("\nsrc=%s", src);
      System.out.printf("\ndest=%s", dest);
      System.out.printf("\ndest.capacity()=%s", dest.capacity());
      System.out.printf("\ndest.length()=%s", dest.length());
   }
}
