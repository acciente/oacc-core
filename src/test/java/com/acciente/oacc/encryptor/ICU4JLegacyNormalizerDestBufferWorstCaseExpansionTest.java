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

import com.ibm.icu.text.Normalizer;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

@RunWith(Parameterized.class)
public class ICU4JLegacyNormalizerDestBufferWorstCaseExpansionTest {

   @Parameters
   public static Object[] data() {
      return new Object[]{
            "foobar",
            "\ufb2c",
            "\ufb2c\ufb2c",
            "\ufb2c\ufb2c\ufb2c",
            "\ufb2c\ufb2c\ufb2c\ufb2c",
            "\u1f82",
            "\ufdfa",
            "\ufb2c\u1f82",
            "\ufb2c\u1f82\ufdfa",
            "\ufb2c\u1f82\ufdfa\ufb2c\u1f82\ufdfa"
      };
   }

   @SuppressWarnings("WeakerAccess")
   @Parameter
   public String src;

   @Test
   public void testExpansion() throws Exception {
      final int expectedMaxExpansionSize = 3 * src.length();

      // allocate the destination to be 3x of the source length
      char[] dest = new char[expectedMaxExpansionSize];

      // normalize the text
      final int actualDestLen = Normalizer.normalize(src.toCharArray(), dest, Normalizer.NFC, 0);
      printStats(src, actualDestLen);
      assertThat(actualDestLen, lessThanOrEqualTo(expectedMaxExpansionSize));
   }

   private void printStats(String src, int destLen) {
      System.out.printf("\nsrc=%s", src);
      System.out.printf("\ndest=%s", destLen);
      System.out.printf("\nsrc.length()=%s", src.length());
      System.out.printf("\ndest.length()=%s", destLen);
   }
}
