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

package com.acciente.oacc.encryptor.jasypt;

import com.acciente.oacc.OaccException;
import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

class HashEncoderDecoder {
   private static final Base64 base64 = new Base64();

   // The following Jasypt digest parameters are values that were used to encrypt password hashes prior to
   // supporting configurable values, these values are important because they are used to decrypt password
   // hashes that have no header (aka legacy password hashes).
   //
   // WARNING:
   // These values are independent of the DEFAULT_ prefixed value defined in the JasyptPasswordEncryptor class,
   // in particular the value in the JasyptPasswordEncryptor class may be changed without adverse affect, but
   // these values should NOT be changed.
   private static final String LEGACY_ENCRYPT_ALGORITHM       = "SHA-256";
   private static final int    LEGACY_ENCRYPT_ITERATIONS      = 100000;
   private static final int    LEGACY_ENCRYPT_SALT_SIZE_BYTES = 16;

   private static final int HASH_PARAMS_ALGORITHM          = 0;
   private static final int HASH_PARAMS_ITERATIONS         = 1;
   private static final int HASH_PARAMS_SALT_SIZE_BYTES    = 2;
   private static final int HASH_PARAMS_ENCRYPTED_PASSWORD = 3;
   private static final int HASH_PARAMS_COUNT              = 4;

   private final String marker;
   private final String paramDelimiter;
   private final String quotedParamDelimiter;

   HashEncoderDecoder(String marker, String paramDelimiter) {
      this.marker = marker;
      this.paramDelimiter = paramDelimiter;
      this.quotedParamDelimiter = Pattern.quote(paramDelimiter);
   }

   String encodeHash(String encryptAlgorithm,
                     int encryptIterations,
                     int encryptSaltSizeBytes,
                     byte[] encryptedPassword) {
      final Object[]      hashParams  = new Object[HASH_PARAMS_COUNT];
      final StringBuilder encodedHash = new StringBuilder(128);

      // setup array of values to encode -- to help ensure same param sequence in encode and decode logic
      hashParams[HASH_PARAMS_ALGORITHM] = encryptAlgorithm;
      hashParams[HASH_PARAMS_ITERATIONS] = encryptIterations;
      hashParams[HASH_PARAMS_SALT_SIZE_BYTES] = encryptSaltSizeBytes;
      hashParams[HASH_PARAMS_ENCRYPTED_PASSWORD] = new String(base64.encode(encryptedPassword), StandardCharsets.US_ASCII);

      encodedHash.append(marker);
      for (int i = 0; i < HASH_PARAMS_COUNT - 1; i++) {
         encodedHash.append(hashParams[i]);
         encodedHash.append(paramDelimiter);
      }
      // encode last param without the delimiter
      encodedHash.append(hashParams[HASH_PARAMS_COUNT - 1]);

      return encodedHash.toString();
   }

   DecodedHash decodeHash(String encryptedPasswordPlusMarker) {
      if (encryptedPasswordPlusMarker.startsWith(marker)) {
         final String[] hashParams = encryptedPasswordPlusMarker.substring(marker.length()).split(quotedParamDelimiter);

         if (hashParams.length != HASH_PARAMS_COUNT) {
            throw new OaccException("Unexpected format for Jasypt hash header: " + encryptedPasswordPlusMarker);
         }

         final String decryptAlgorithm;
         final int    decryptIterations;
         final int    decryptSaltSizeBytes;
         final byte[] encryptedPassword;
         decryptAlgorithm = hashParams[HASH_PARAMS_ALGORITHM];
         try {
            decryptIterations = Integer.parseInt(hashParams[HASH_PARAMS_ITERATIONS]);
            decryptSaltSizeBytes = Integer.parseInt(hashParams[HASH_PARAMS_SALT_SIZE_BYTES]);
         }
         catch (NumberFormatException e) {
            throw new OaccException("Unexpected value in Jasypt hash header (for iterations and/or salt size): " + encryptedPasswordPlusMarker);
         }
         encryptedPassword = base64.decode(hashParams[HASH_PARAMS_ENCRYPTED_PASSWORD].getBytes(StandardCharsets.US_ASCII));

         return new DecodedHash.Builder()
               .withEncryptAlgorithm(decryptAlgorithm)
               .withEncryptIterations(decryptIterations)
               .withEncryptSaltSizeBytes(decryptSaltSizeBytes)
               .withEncryptedPassword(encryptedPassword)
               .build();
      }
      else {
         // if no marker is present we assume this is a legacy Jasypt hash (no marker is present in these hashes)

         final byte[] encryptedPassword = base64.decode(encryptedPasswordPlusMarker.getBytes(StandardCharsets.US_ASCII));

         return new DecodedHash.Builder()
               .withEncryptAlgorithm(LEGACY_ENCRYPT_ALGORITHM)
               .withEncryptIterations(LEGACY_ENCRYPT_ITERATIONS)
               .withEncryptSaltSizeBytes(LEGACY_ENCRYPT_SALT_SIZE_BYTES)
               .withEncryptedPassword(encryptedPassword)
               .build();
      }
   }
}
