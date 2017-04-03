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
import com.ibm.icu.text.Normalizer;

public class ICU4JTextNormalizerForICU4JBelowVersion4dot6 extends TextNormalizer {
   // constants
   private static final char ZERO_CHAR = '\0';

   // singleton instance
   private static class SingletonHolder {
      private static final TextNormalizer instance = new ICU4JTextNormalizerForICU4JBelowVersion4dot6();
   }

   private ICU4JTextNormalizerForICU4JBelowVersion4dot6() {
      // dummy call to trigger loading the Normalize class
      Normalizer.normalize("", Normalizer.NFC, 0);
   }

   public static TextNormalizer getInstance() {
      return SingletonHolder.instance;
   }

   @Override
   public char[] normalizeToNfc(char[] source) {
      int destBufferSize = 3 * source.length;
      char[] result = null;
      do {
         char[] destBuffer = new char[destBufferSize];
         try {
            final int destBufferUsedCount = Normalizer.normalize(source, destBuffer, Normalizer.NFC, 0);
            result = copyContents(destBuffer, destBufferUsedCount);
         }
         catch (IndexOutOfBoundsException e) {
            // NOTE: since we allocate an initial buffer that is 3x of
            // the source text length we never expect this to happen

            // try the next loop iteration with a larger buffer
            destBufferSize += source.length;
         }
         finally {
            // zero out the current dest buffer
            zeroOut(destBuffer);
         }
      } while (result == null);

      return result;
   }

   /**
    * Returns a copy of the contents of specified char array
    *
    * @param source char array to copy from
    * @param countToCopy the number of characters to copy from the source
    *
    * @return a character array with
    */
   private char[] copyContents(char[] source, int countToCopy) {
      final char[] copy = new char[countToCopy];
      System.arraycopy(source, 0, copy, 0, countToCopy);
      return copy;
   }

   /**
    * Sets all contents in the specified char array to {@value ZERO_CHAR}.
    *
    * @param dest the char array to zero out
    */
   private void zeroOut(char[] dest) {
      for (int i = 0; i < dest.length; i++) {
         dest[i] = ZERO_CHAR;
      }
   }
}
