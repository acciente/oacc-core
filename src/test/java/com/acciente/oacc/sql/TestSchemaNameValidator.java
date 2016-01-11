/*
 * Copyright 2009-2016, Acciente LLC
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
package com.acciente.oacc.sql;

import com.acciente.oacc.sql.internal.SchemaNameValidator;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TestSchemaNameValidator {
   final String unicodeWord = "оацц_123";

   final String delim_double      = "\"";
   final String delim_single      = "'";
   final String delim_squareOpen  = "[";
   final String delim_squareClose = "]";
   final String delim_backtick    = "`";

   @Test
   public void isValid_null_shouldSucceed() {
      assertThat(SchemaNameValidator.isValid(null), is(true));
   }

   @Test
   public void isValid_undelimited_shouldSucceed() {
      assertThat(SchemaNameValidator.isValid(unicodeWord), is(true));
      assertThat(SchemaNameValidator.isValid("__OACC__"), is(true));
   }

   @Test
   public void isValid_delimited_shouldSucceed() {
      assertThat(SchemaNameValidator.isValid(delim_double + unicodeWord + delim_double), is(true));
      assertThat(SchemaNameValidator.isValid(delim_single + unicodeWord + delim_single), is(true));
      assertThat(SchemaNameValidator.isValid(delim_squareOpen + unicodeWord + delim_squareClose), is(true));
      assertThat(SchemaNameValidator.isValid(delim_backtick + unicodeWord + delim_backtick), is(true));
   }

   @Test
   public void isValid_delimited_shouldFail() {
      assertThat(SchemaNameValidator.isValid(unicodeWord + delim_double), is(false));
      assertThat(SchemaNameValidator.isValid(delim_double + unicodeWord), is(false));
      assertThat(SchemaNameValidator.isValid(unicodeWord + delim_single), is(false));
      assertThat(SchemaNameValidator.isValid(delim_single + unicodeWord), is(false));
      assertThat(SchemaNameValidator.isValid(unicodeWord + delim_squareClose), is(false));
      assertThat(SchemaNameValidator.isValid(delim_squareClose + unicodeWord), is(false));
      assertThat(SchemaNameValidator.isValid(unicodeWord + delim_squareOpen), is(false));
      assertThat(SchemaNameValidator.isValid(delim_squareOpen + unicodeWord), is(false));
      assertThat(SchemaNameValidator.isValid(unicodeWord + delim_backtick), is(false));
      assertThat(SchemaNameValidator.isValid(delim_backtick + unicodeWord), is(false));

      assertThat(SchemaNameValidator.isValid(delim_double      + unicodeWord + delim_single), is(false));
      assertThat(SchemaNameValidator.isValid(delim_single      + unicodeWord + delim_double), is(false));
      assertThat(SchemaNameValidator.isValid(delim_squareClose + unicodeWord + delim_squareOpen), is(false));
      assertThat(SchemaNameValidator.isValid(delim_backtick    + unicodeWord + delim_single), is(false));

      assertThat(SchemaNameValidator.isValid("oac" + delim_double     + "c_1" + delim_double      + "23"), is(false));
      assertThat(SchemaNameValidator.isValid("oac" + delim_single     + "c_1" + delim_single      + "23"), is(false));
      assertThat(SchemaNameValidator.isValid("oac" + delim_squareOpen + "c_1" + delim_squareClose + "23"), is(false));
      assertThat(SchemaNameValidator.isValid("oac" + delim_backtick   + "c_1" + delim_backtick    + "23"), is(false));
   }

   @Test
   public void isValid_specialCharacters_shouldFail() {
      assertThat(SchemaNameValidator.isValid(";"), is(false));
      assertThat(SchemaNameValidator.isValid("/"), is(false));
      assertThat(SchemaNameValidator.isValid("--"), is(false));

      assertThat(SchemaNameValidator.isValid("oacc 123"), is(false));
      assertThat(SchemaNameValidator.isValid("oacc-123"), is(false));
      assertThat(SchemaNameValidator.isValid("oacc.123"), is(false));

      assertThat(SchemaNameValidator.isValid("Robert'); DROP TABLE students;--"), is(false));
   }

   @Test
   public void isValid_blank_shouldFail() {
      assertThat(SchemaNameValidator.isValid(""), is(false));
      assertThat(SchemaNameValidator.isValid(" "), is(false));
      assertThat(SchemaNameValidator.isValid("\t"), is(false));
   }
}
