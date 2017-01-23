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
package com.acciente.oacc;

import com.acciente.oacc.encryptor.PasswordEncryptor;
import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.digest.StandardByteDigester;
import org.jasypt.normalization.Normalizer;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class JasyptPasswordEncryptorFromOACCv2_00_rc7 implements PasswordEncryptor {
   private final StandardByteDigester digester;
   private final Base64               base64;

   public JasyptPasswordEncryptorFromOACCv2_00_rc7() {
      this.digester = new StandardByteDigester();
      this.digester.setAlgorithm("SHA-256");
      this.digester.setIterations(100000);
      this.digester.setSaltSizeBytes(16);
      this.digester.initialize();
      this.base64 = new Base64();
   }

   @Override
   public String encryptPassword(final char[] password) {
      if (password == null) {
         return null;
      }

      final byte[] digest = this.digester.digest(getCleanedBytes(password));

      return new String(this.base64.encode(digest), StandardCharsets.US_ASCII);
   }

   @Override
   public boolean checkPassword(final char[] plainPassword,
                                final String encryptedPassword) {
      if (plainPassword == null) {
         return (encryptedPassword == null);
      }
      else if (encryptedPassword == null) {
         return false;
      }

      return this.digester.matches(getCleanedBytes(plainPassword),
                                   this.base64.decode(encryptedPassword.getBytes(StandardCharsets.US_ASCII)));
   }

   private byte[] getCleanedBytes(char[] password) {
      final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(Normalizer.normalizeToNfc(password)));
      final byte[] byteArray = new byte[byteBuffer.remaining()];
      byteBuffer.get(byteArray);
      Arrays.fill(byteBuffer.array(), (byte) 0);
      return byteArray;
   }
}
