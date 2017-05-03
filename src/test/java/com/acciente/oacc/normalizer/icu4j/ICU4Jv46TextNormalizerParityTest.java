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

package com.acciente.oacc.normalizer.icu4j;

import com.acciente.oacc.normalizer.TextNormalizer;
import com.ibm.icu.text.Normalizer2;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.CharBuffer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class ICU4Jv46TextNormalizerParityTest {
   private final TextNormalizer textNormalizer = ICU4Jv46TextNormalizer.getInstance();
   private final Normalizer2    normalizer     = Normalizer2Factory.getNFCInstance();

   @Parameterized.Parameters
   public static Object[] data() {
      return new Object[]{
            "The big brown fox jumps over 2 picket fences ^^ !".toCharArray(),
            "¢£©®°ª¹²³ ¼½¾äöüÅé".toCharArray(),    // latin-1
            new char[]{0x212b, 0x2126},            // angstrom-sign (Å), ohm-sign (Ω)
            new char[]{'A', 0x30a},                // A, combining-ring-above
            new char[]{'q', 0x307, 0x323},         // q, dot-above, dot-below
            new char[]{0x1e0b, 0x323},             // d-with-dot-above (ḋ), dot-below
            new char[]{'2', 0x2075}                // 2, superscript-5 (⁵)
      };
   }

   @Parameterized.Parameter
   public char[] srcCharArray;

   @Test
   public void testParityWithUnderlyingNormalizer() throws Exception {
      final char[] expectedResult = normalizeDirect();
      final char[] actualResult   = textNormalizer.normalizeToNfc(srcCharArray);

      assertEquals(actualResult.length, expectedResult.length);
      assertArrayEquals(expectedResult, actualResult);
   }

   private char[] normalizeDirect() {
      // normalize using direct call to underlying normalizer
      final StringBuilder destStringBuilder = new StringBuilder(2 * srcCharArray.length);
      normalizer.normalize(CharBuffer.wrap(srcCharArray), destStringBuilder);
      return destStringBuilder.toString().toCharArray();
   }
}