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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.runners.Parameterized.Parameter;
import static org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TextNormalizerTest {
   private static final ICU4JTextNormalizer icu4JTextNormalizer = ICU4JTextNormalizer.getTextNormalizer();
   private static final JDKTextNormalizer   jdkTextNormalizer   = JDKTextNormalizer.getTextNormalizer();

   @Parameters
   public static Object[] data() {
      return new Object[]{icu4JTextNormalizer, jdkTextNormalizer};
   }

   @Parameter
   public TextNormalizer textNormalizer;

   @Test
   public void testNormalizationA() throws Exception {
      final char[] input    = "The big brown fox jumps over the picket fence".toCharArray();
      final char[] expected = input;

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void testNormalizationOfSwedishLetter_Å() throws Exception {
      final char[] input    = new char[]{0x212b}; // U+212B -- angstrom sign "Å")
      final char[] expected = new char[]{0x00c5};

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void testNormalizationOfVietnameseLetter_ế() throws Exception {
      final char[] input    = new char[]{0x1ebf}; // U+1EBF (ế) -- Vietnamese
      final char[] expected = new char[]{0x1ebf};

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void testNormalizationOfSequence1() throws Exception {
      final char[] input    = new char[]{0x212b, 0x2126};
      final char[] expected = new char[]{0x00c5, 0x03a9};

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void testNormalizationOfSequence2() throws Exception {
      final char[] input    = new char[]{0x212b, 0x2126, 0x1e0b, 0x0323};
      final char[] expected = new char[]{0x00c5, 0x03a9, 0x1e0d, 0x0307};

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void testNormalizationOfSequence3() throws Exception {
      final char[] input    = new char[]{0x03d3, 0x03d4, 0x1e9b};
      final char[] expected = new char[]{0x03d3, 0x03d4, 0x1e9b};

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }
}