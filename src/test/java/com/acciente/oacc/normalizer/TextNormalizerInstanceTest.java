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

import com.acciente.oacc.normalizer.icu4j.ICU4Jv46TextNormalizer;
import org.junit.Test;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

public class TextNormalizerInstanceTest {
   /**
    * This test should pass if and only if ICU4J 4.6 or higher is in the classpath
    */
   @Test
   public void testReturnsICU4JTextNormalizer() {
      final TextNormalizer textNormalizer = TextNormalizer.getInstance();
      assertThat(textNormalizer.getClass().getCanonicalName(),
                 equalTo(ICU4Jv46TextNormalizer.class.getCanonicalName()));
   }
}