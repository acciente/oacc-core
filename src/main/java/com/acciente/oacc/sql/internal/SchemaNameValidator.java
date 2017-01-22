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
package com.acciente.oacc.sql.internal;

import java.util.regex.Pattern;

public class SchemaNameValidator {
   // breakdown of the regex: (?U)^\w+|^"\w+"|^'\w+'|^\[\w+\]|^`\w+`
   // ------------------------------------------------------------
   // (?U)      embedded flag to set UNICODE_CHARACTER_CLASS
   // ^\w+      match sequence of unicode word characters
   // |^"\w+"   or match sequence of unicode word characters delimited by double quotes
   // |^'\w+'   or match sequence of unicode word characters delimited by single quotes
   // |^\[\w+\] or match sequence of unicode word characters delimited by square brackets
   // |^`\w+`   or match sequence of unicode word characters delimited by backticks
   public static final String  OPTIONALLY_DELIMITED_UNICODE_WORD_REGEX   = "(?U)^\\w+|^\"\\w+\"|^'\\w+'|^\\[\\w+\\]|^`\\w+`";
   public static final Pattern OPTIONALLY_DELIMITED_UNICODE_WORD_PATTERN = Pattern.compile(OPTIONALLY_DELIMITED_UNICODE_WORD_REGEX);

   /**
    * Validates the specified schema name.
    * <p/>
    * The specified schema name is only considered valid if it consists of a single sequence of unicode word characters,
    * or is null. Blank schema names are not valid.
    * The unicode word can optionally be surrounded by SQL delimiters.
    * Valid SQL delimiters include the following characters:
    * <ul>
    *    <li>double-quote (<code>"</code>)</li>
    *    <li>single-quote (<code>'</code>)</li>
    *    <li>square brackets (<code>[]</code>)</li>
    *    <li>backtick (<code>`</code>)</li>
    * </ul>
    * A unicode word can consist of the following
    * <a href="https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html#ubpc">[Javadoc Reference]</a>:
    * <ul>
    *    <li>Alphabetical letter characters</li>
    *    <li>Digits</li>
    *    <li>Connector punctuation (e.g. underscore "<code>_</code>")</li>
    *    <li>Nonspacing marks</li>
    *    <li>Enclosing marks</li>
    *    <li>Spacing combining marks</li>
    * </ul>
    *
    * @param schemaName   the schema name String to be validated
    * @return true if the specified schema name is null or a (optionally delimited) unicode word, false otherwise
    */
   public static boolean isValid(String schemaName) {
      return schemaName == null || OPTIONALLY_DELIMITED_UNICODE_WORD_PATTERN.matcher(schemaName).matches();
   }

   /**
    * Asserts the specified schema name is valid.
    *
    * See {@link #isValid(String)}.
    * @param schemaName the schema name String to be validated
    * @throws IllegalArgumentException if the specified schema name is not valid according to {@link #isValid(String)}}
    */
   public static void assertValid(String schemaName) {
      if (!isValid(schemaName)) {
         throw new IllegalArgumentException("Invalid database schema name - it can only consist of (optionally delimited) "
                                                  + "unicode word characters, or be null, but it was: " + schemaName);
      }
   }
}
