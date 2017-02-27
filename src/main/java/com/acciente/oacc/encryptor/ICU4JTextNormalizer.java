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

import com.ibm.icu.text.Normalizer2;

import java.nio.CharBuffer;

public class ICU4JTextNormalizer extends TextNormalizer {
   // constants
   private static final char ZERO_CHAR = 0;

   // state
   private final Normalizer2 nfcNormalizer;

   // singleton instance
   private static final ICU4JTextNormalizer singletonTextNormalizer = new ICU4JTextNormalizer();

   private ICU4JTextNormalizer() {
      nfcNormalizer = Normalizer2.getNFCInstance();
   }

   public static ICU4JTextNormalizer getTextNormalizer() {
      return singletonTextNormalizer;
   }

   @Override
   public char[] normalizeToNfc(char[] charArraySource) {
      final StringBuilder stringBuilderDest = new StringBuilder(charArraySource.length + 16);
      nfcNormalizer.normalize(CharBuffer.wrap(charArraySource), stringBuilderDest);

      // copy the result out of the StringBuilder, before clearing the character array buffer backing the StringBuilder
      final char[] charArrayDest = copyContents(stringBuilderDest);

      // zero out contents of the character array backing the StringBuilder
      zeroOut(stringBuilderDest);

      return charArrayDest;
   }

   /**
    * Returns a copy of the contents of specified string builder.
    *
    * @param source
    * @return a character array
    */
   private char[] copyContents(StringBuilder source) {
      final char[] copy = new char[source.length()];
      source.getChars(0, copy.length, copy, 0);
      return copy;
   }

   /**
    * Sets all contents in the specified string builder to {@value ZERO_CHAR}.
    *
    * @param dest the StringBuilder to zero out
    */
   private void zeroOut(StringBuilder dest) {
      for (int i = 0; i < dest.length(); i++) {
         dest.setCharAt(i, ZERO_CHAR);
      }
   }
}
