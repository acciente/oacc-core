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

package com.acciente.oacc.normalizer.jdk;

import com.acciente.oacc.normalizer.TextNormalizer;

import java.nio.CharBuffer;
import java.text.Normalizer;

public class JDKTextNormalizer extends TextNormalizer {
   // we use the singleton holder pattern to lazy initialize the singleton instance
   // in a thread safe manner without the need for any explicit locking
   // (see https://en.wikipedia.org/wiki/Initialization-on-demand_holder_idiom).
   private static class LazyInitSingletonHolder {
      private static final TextNormalizer INSTANCE = new JDKTextNormalizer();
   }

   private JDKTextNormalizer() {
   }

   public static TextNormalizer getInstance() {
      return LazyInitSingletonHolder.INSTANCE;
   }

   @Override
   public char[] normalizeToNfc(char[] source) {
      return Normalizer.normalize(CharBuffer.wrap(source), Normalizer.Form.NFC).toCharArray();
   }
}
