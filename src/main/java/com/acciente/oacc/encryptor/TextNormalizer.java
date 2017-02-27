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

/**
 * This class normalizes Unicode plaintext that use characters that have more than one possible representation. This is
 * important because use may not always be aware of how their password text was encoded, since different possible
 * encodings visually look the same to the user. For example the sequence ffi may be represented as three separate
 * characters or as a single ligature.
 * <p>
 * This class first tries to use the ICU4J library for normalization since it allows normalization of text in character
 * arrays without converting to string. If ICU4J is not available, then it falls back to the text normalizer in the JDK
 * which *does* require the character array to be converted to String.
 */
public abstract class TextNormalizer {
   /**
    * This method first tries to use the ICU4J library for normalization since it allows normalization of text in
    * character arrays without converting to string. If ICU4J is not available, then it falls back to the text
    * normalizer in the JDK which *does* require the character array to be converted to String.
    *
    * @return a text normalizer instance
    */
   public static TextNormalizer getTextNormalizer() {
      try {
         return ICU4JTextNormalizer.getTextNormalizer();
      }
      catch (Exception e) {
         return JDKTextNormalizer.getTextNormalizer();
      }
   }

   /**
    * Returns the normalized version of the password.
    *
    * @param source a plaintext password
    * @return a normalized string
    */
   public abstract char[] normalizeToNfc(char[] source);
}
