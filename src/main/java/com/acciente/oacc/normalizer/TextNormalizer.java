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

package com.acciente.oacc.normalizer;

import com.acciente.oacc.normalizer.icu4j.ICU4Jv26TextNormalizer;
import com.acciente.oacc.normalizer.icu4j.ICU4Jv46TextNormalizer;
import com.acciente.oacc.normalizer.jdk.JDKTextNormalizer;

/**
 * Normalizes Unicode text to handle characters that have more than one canonically equivalent representation.
 * <p>
 * This is important when comparing hashed passwords because plaintext that visually looks the same might actually
 * be represented differently binarily, without the user being aware. For example, `é` (the letter `e` with accent acute)
 * may be represented as a single Unicode character (U+00E9) or composed of two characters (U+0065 + U+0301), but both
 * representations are canonically equivalent.
 * <p>
 * This class first tries to use the ICU4J library for normalization because it normalizes character arrays
 * without converting to <code>String</code>. If ICU4J is not available, then it falls back to the text normalizer
 * provided by the JDK, which produces an **intermediate <code>String</code> representation** of the text.
 * <p>
 * In other words, if you need to prevent a cleanable <code>char[]</code> password being turned into a temporary
 * <code>String</code> during Unicode character normalization, you need to include a dependency to ICU4J.
 */
public abstract class TextNormalizer {
   /**
    * Get an instance of a text normalizer.
    * <p>
    * If the ICU4J library is available, the returned instance will use an ICU4J normalizer, which handles character
    * arrays without converting to <code>String</code>. Otherwise (if ICU4J is not available), the fallback instance
    * returned uses the normalizer provided by the JDK, which produces an **intermediate <code>String</code>
    * representation** of the normalized text.
    *
    * @return a text normalizer instance
    */
   public static TextNormalizer getInstance() {
      try {
         // first see if a newer version of ICU4J is available
         return ICU4Jv46TextNormalizer.getInstance();
      }
      catch (NoClassDefFoundError e1) {
         try {
            // next see if an older version of ICU4J is available
            return ICU4Jv26TextNormalizer.getInstance();
         }
         catch (NoClassDefFoundError e2) {
            // otherwise fallback to the non-cleanable JDK based implementation
            return JDKTextNormalizer.getInstance();
         }
      }
   }

   /**
    * Returns the canonically equivalent normalized (NFC) version of a Unicode character array.
    * <p>
    * Note:
    * If the ICU4J library for normalization is not available, the fallback Normalizer provided by the JDK
    * will produce an intermediate <code>String</code> representation of the normalized text!
    *
    * @param source any Unicode text
    * @return a character array containing the normalized representation of the source text
    */
   public abstract char[] normalizeToNfc(char[] source);
}
