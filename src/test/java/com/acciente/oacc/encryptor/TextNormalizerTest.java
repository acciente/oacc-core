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
import static org.hamcrest.CoreMatchers.not;
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
   public void normalizeToNfc_asciiUnchanged() throws Exception {
      final char[] input    = "The big brown fox jumps over 2 picket fences ^^ !".toCharArray();
      final char[] expected = input;

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void normalizeToNfc_latin1Unchanged() throws Exception {
      final char[] input    = "¢£©®°ª¹²³ ¼½¾äöüÅé".toCharArray();
      final char[] expected = input;

      final char[] actual = textNormalizer.normalizeToNfc(input);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void normalizeToNfc_singletons() throws Exception {
      final char[] singletons = new char[]{0x212b, 0x2126}; // angstrom-sign (Å), ohm-sign (Ω)
      final char[] expected = new char[]{0x00c5, 0x03a9};   // latin-capital-a-with-ring-above (Å), omega (Ω)

      final char[] actual = textNormalizer.normalizeToNfc(singletons);

      assertThat(actual, equalTo(expected));
   }

   @Test
   public void normalizeToNfc_combiningSequence() throws Exception {
      final char[] combiningSequence = new char[]{'A', 0x30a}; // A, combining-ring-above
      final char[] singleCharacter = new char[]{0x00c5};       // latin-capital-a-with-ring-above (Å)

      final char[] normalizedSequence = textNormalizer.normalizeToNfc(combiningSequence);
      final char[] normalizedCharacter = textNormalizer.normalizeToNfc(singleCharacter);

      assertThat(normalizedSequence, equalTo(normalizedCharacter));
   }

   @Test
   public void normalizeToNfc_combiningMarkOrder() throws Exception {
      final char[] sequence_ab = new char[]{'q', 0x307, 0x323}; // q, dot-above, dot-below
      final char[] sequence_ba = new char[]{'q', 0x323, 0x307}; // q, dot-below, dot-above

      final char[] normalized_ab = textNormalizer.normalizeToNfc(sequence_ab);
      final char[] normalized_ba = textNormalizer.normalizeToNfc(sequence_ba);

      assertThat(normalized_ab, equalTo(normalized_ba));
   }

   @Test
   public void normalizeToNfc_differentPrecomposedCharacterAndCombiningMark() throws Exception {
      final char[] sequence_ab = new char[]{0x1e0b, 0x323}; // d-with-dot-above (ḋ), dot-below
      final char[] sequence_cd = new char[]{0x1e0d, 0x307}; // d-with-dot-below (ḍ), dot-above

      final char[] normalized_ab = textNormalizer.normalizeToNfc(sequence_ab);
      final char[] normalized_cd = textNormalizer.normalizeToNfc(sequence_cd);

      assertThat(normalized_ab, equalTo(normalized_cd));
   }

   @Test
   public void normalizeToNfc_compatibilityEquivalentOnly() throws Exception {
      final char[] sequence_ab = new char[]{'2', 0x2075}; // 2, superscript-5 (⁵)
      final char[] sequence_ac = new char[]{'2', '5'};

      final char[] normalized_ab = textNormalizer.normalizeToNfc(sequence_ab);
      final char[] normalized_ac = textNormalizer.normalizeToNfc(sequence_ac);

      assertThat(normalized_ab, not(equalTo(normalized_ac)));
   }
}