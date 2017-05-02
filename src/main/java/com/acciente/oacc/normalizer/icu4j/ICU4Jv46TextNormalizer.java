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

import java.nio.CharBuffer;

/**
 * Why is there this specific implementation of the TextNormalizer for ICU4J version 4.6 and higher?
 * -------------------------------------------------------------------------------------------------
 * In ICU4J versions prior to version 4.6 the methods to normalize text were in a class named Normalizer.
 * Starting with ICU4J version 4.6 there is a new class named Normalizer2 with the normalization methods,
 * and the methods in the old Normalizer class delegate to the methods in the new Normalizer2 class.
 *
 * The legacy Normalizer class delegates to a method of the new Normalizer2 class that allocates an internal
 * working StringBuilder that is not externally accessible and therefore not cleanable.
 *
 * This class directly uses the new Normalizer2 via the method does *not* allocate an internal working
 * StringBuilder, it also takes precautions to minimize the chance of the Normalizer2 leaking an
 * inaccessible/non-cleanable buffer containing the source text (for details see note below about
 * "Using ICU4J to ensure cleanable passwords").
 */
public class ICU4Jv46TextNormalizer extends TextNormalizer {
   // constants
   private static final char ZERO_CHAR = '\0';

   // state
   private final Normalizer2 nfcNormalizer;

   // we use the singleton holder pattern to lazy initialize the singleton instance
   // in a thread safe manner without the need for any explicit locking
   // (see https://en.wikipedia.org/wiki/Initialization-on-demand_holder_idiom).
   private static class LazyInitSingletonHolder {
      private static final TextNormalizer INSTANCE = new ICU4Jv46TextNormalizer();
   }

   private ICU4Jv46TextNormalizer() {
      nfcNormalizer = Normalizer2Factory.getNFCInstance();
   }

   public static TextNormalizer getInstance() {
      return LazyInitSingletonHolder.INSTANCE;
   }

   @Override
   public char[] normalizeToNfc(char[] charArraySource) {
      /*
       * Using ICU4J to ensure cleanable passwords
       * -----------------------------------------
       * Using ICU4J, without requisite precautions, does not ensure that the contents of the source
       * char sequence is not copied to a sequence that not accessible to the caller -- and therefore
       * not cleanable. The following two precautions needed are:
       *
       * 1) Only use the Normalizer2#normalize(CharSequence, StringBuilder) method. While it is
       * clear that the Normalizer2#normalize(CharSequence) method should not be used (since it
       * returns an immutable string) it turns out that we also need to avoid using the
       * Normalizer2#normalize(CharSequence, Appendable) method since it allocates an internal
       * StringBuilder instance for intermediate processing. In contrast, the
       * Normalizer2#normalize(CharSequence, StringBuilder) method uses the caller-provided
       * StringBuilder for the intermediate processing, which now takes us to the next precaution
       * needed.
       *
       * 2) When using the {@link Normalizer2#normalize(CharSequence, StringBuilder)} method, if the
       * destination StringBuilder does not have sufficient capacity and is automatically expanded, then
       * we cause a non-cleanable char array with the partial contents to be "leaked" (i.e. we have no
       * access to this char array). This is because to increase its capacity the StringBuilder allocates
       * a new char array buffer, and releases its reference to the old buffer with its contents intact.
       * To prevent this we need to allocate a destination StringBuilder with enough capacity to handle
       * the maximum expansion that can occur during NFC normalization. How much capacity do we need to
       * allocate?
       *
       * According to (http://unicode.org/faq/normalization.html#12) the worst expansion for NFC is 3x. In
       * tests of the ICU4J implementation, using the Unicode characters that cause the worst case expansion,
       * it was verified that if the destination StringBuilder has a 3x initial capacity then the
       * StringBuilder capacity does not increase (see ICU4JNormalizer2DestBufferWorstCaseExpansionTest).
       */
      final StringBuilder stringBuilderDest = new StringBuilder(3 * charArraySource.length);
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
      dest.setLength(dest.capacity());
      for (int i = 0; i < dest.length(); i++) {
         dest.setCharAt(i, ZERO_CHAR);
      }
      dest.setLength(0);
   }
}
