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

import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

class PasswordEncoderDecoder {
   private static final String MARKER                 = JasyptPasswordEncryptor.NAME + ":";
   private static final String PARAM_DELIMITER        = "$";
   private static final String QUOTED_PARAM_DELIMITER = Pattern.quote(PARAM_DELIMITER);

   private static final int DECODED_PASSWORD_ARRAY_ALGORITHM       = 0;
   private static final int DECODED_PASSWORD_ARRAY_ITERATIONS      = 1;
   private static final int DECODED_PASSWORD_ARRAY_SALT_SIZE_BYTES = 2;
   private static final int DECODED_PASSWORD_ARRAY_DIGEST          = 3;
   private static final int DECODED_PASSWORD_ARRAY_COUNT           = 4;

   private static final Base64 base64 = new Base64();

   /**
    * Encodes an identifying header, the parameters used to generate the Jasypt digest, and the Jasypt digest into a
    * single "self-contained" password that contains enough information for future comparisons.
    *
    * @param algorithm     the algorithm used to generate the digest.
    * @param iterations    the number of iterations used to generate the digest.
    * @param saltSizeBytes the salt size bytes used to generate the digest.
    * @param digest        the digest itself.
    * @return a fully-encoded password ready for persistent storage.
    */
   String encode(String algorithm,
                 int iterations,
                 int saltSizeBytes,
                 byte[] digest) {
      // setup array of values to encode -- to help ensure same param sequence in encode and decode logic
      final Object[] decodedPasswordArray = new Object[DECODED_PASSWORD_ARRAY_COUNT];
      decodedPasswordArray[DECODED_PASSWORD_ARRAY_ALGORITHM] = algorithm;
      decodedPasswordArray[DECODED_PASSWORD_ARRAY_ITERATIONS] = iterations;
      decodedPasswordArray[DECODED_PASSWORD_ARRAY_SALT_SIZE_BYTES] = saltSizeBytes;
      decodedPasswordArray[DECODED_PASSWORD_ARRAY_DIGEST] = new String(base64.encode(digest), StandardCharsets.US_ASCII);

      final StringBuilder encodedPassword = new StringBuilder(128).append(MARKER);
      for (int i = 0; i < DECODED_PASSWORD_ARRAY_COUNT - 1; i++) {
         encodedPassword.append(decodedPasswordArray[i]);
         encodedPassword.append(PARAM_DELIMITER);
      }
      // encode last param without the delimiter
      encodedPassword.append(decodedPasswordArray[DECODED_PASSWORD_ARRAY_COUNT - 1]);

      return encodedPassword.toString();
   }

   /**
    * Decodes a previously encoded Jasypt password into its constituent parts (algorithm, iterations, salt size, digest).
    *
    * @param encodedPassword an encoded password that was previously returned by
    *                        {{@link #encode(String, int, int, byte[])}}.
    * @return an object containing the decoded parts of the password (algorithm, iterations, salt size, digest).
    */
   DecodedPassword decode(String encodedPassword) {
      if (encodedPassword.startsWith(MARKER)) {
         final String[] decodedPasswordArray = encodedPassword.substring(MARKER.length()).split(QUOTED_PARAM_DELIMITER);

         if (decodedPasswordArray.length != DECODED_PASSWORD_ARRAY_COUNT) {
            throw new IllegalArgumentException("Unexpected format for Jasypt password: " +
                                                     encodedPassword.substring(0, MARKER.length()));
         }

         final String algorithm;
         final int    iterations;
         final int    saltSizeBytes;
         final byte[] digest;

         algorithm = decodedPasswordArray[DECODED_PASSWORD_ARRAY_ALGORITHM];
         try {
            iterations = Integer.parseInt(decodedPasswordArray[DECODED_PASSWORD_ARRAY_ITERATIONS]);
            saltSizeBytes = Integer.parseInt(decodedPasswordArray[DECODED_PASSWORD_ARRAY_SALT_SIZE_BYTES]);
         }
         catch (NumberFormatException e) {
            throw new IllegalArgumentException("Unexpected value in Jasypt password header for iterations and/or salt size: " + encodedPassword);
         }
         digest = base64.decode(decodedPasswordArray[DECODED_PASSWORD_ARRAY_DIGEST].getBytes(StandardCharsets.US_ASCII));

         return new DecodedPassword.Builder()
               .algorithm(algorithm)
               .iterations(iterations)
               .saltSizeBytes(saltSizeBytes)
               .digest(digest)
               .build();
      }
      else {
         throw new IllegalArgumentException("Unexpected marker for Jasypt password: " +
                                                  encodedPassword.substring(0, MARKER.length()));
      }
   }
}
