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
package com.acciente.oacc.sql.internal.encryptor;

import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.digest.StandardByteDigester;
import org.jasypt.normalization.Normalizer;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class JasyptPasswordEncryptor implements PasswordEncryptor, Serializable {
   static final String NAME = "jasypt";

   private static final String               marker   = NAME + ":";
   private static final StandardByteDigester digester = newStandardByteDigester();
   private static final Base64               base64   = new Base64();

   private static final JasyptPasswordEncryptor singletonInstance = new JasyptPasswordEncryptor();

   private JasyptPasswordEncryptor() {
   }

   public static JasyptPasswordEncryptor getPasswordEncryptor() {
      return singletonInstance;
   }

   @Override
   public String encryptPassword(final char[] password) {
      return __encryptPassword(password);
   }

   private static String __encryptPassword(char[] password) {
      if (password == null) {
         return null;
      }

      final byte[] digest = digester.digest(getCleanedBytes(password));

      return addMarker(new String(base64.encode(digest), StandardCharsets.US_ASCII));
   }

   @Override
   public boolean checkPassword(final char[] plainPassword,
                                final String encryptedPassword) {
      return __checkPassword(plainPassword, encryptedPassword);
   }

   private static boolean __checkPassword(char[] plainPassword, String encryptedPassword) {
      if (plainPassword == null) {
         return (encryptedPassword == null);
      }
      else if (encryptedPassword == null) {
         return false;
      }

      return digester.matches(getCleanedBytes(plainPassword),
                              base64.decode(subtractMarker(encryptedPassword).getBytes(StandardCharsets.US_ASCII)));
   }

   private static String addMarker(String encryptedPassword) {
      return marker + encryptedPassword;
   }

   private static String subtractMarker(String encryptedPasswordPlusMarker) {
      if (encryptedPasswordPlusMarker.startsWith(marker)) {
         return encryptedPasswordPlusMarker.substring(marker.length());
      }
      // if no marker is present we assume this is a legacy Jasypt hash (no marker is present in these hashes)
      return encryptedPasswordPlusMarker;
   }

   private static StandardByteDigester newStandardByteDigester() {
      final StandardByteDigester standardByteDigester = new StandardByteDigester();
      standardByteDigester.setAlgorithm("SHA-256");
      standardByteDigester.setIterations(100000);
      standardByteDigester.setSaltSizeBytes(16);
      standardByteDigester.initialize();
      return standardByteDigester;
   }

   private static byte[] getCleanedBytes(char[] password) {
      final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(Normalizer.normalizeToNfc(password)));
      final byte[]     byteArray  = new byte[byteBuffer.remaining()];
      byteBuffer.get(byteArray);
      Arrays.fill(byteBuffer.array(), (byte) 0);
      return byteArray;
   }
}
