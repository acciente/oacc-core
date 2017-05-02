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

class DecodedPassword {
   private final String algorithm;
   private final int    iterations;
   private final int    saltSizeBytes;
   private final byte[] digest;

   private DecodedPassword(Builder builder) {
      algorithm = builder.algorithm;
      iterations = builder.iterations;
      saltSizeBytes = builder.saltSizeBytes;
      digest = builder.digest;
   }

   String getAlgorithm() {
      return algorithm;
   }

   int getIterations() {
      return iterations;
   }

   int getSaltSizeBytes() {
      return saltSizeBytes;
   }

   byte[] getDigest() {
      return digest;
   }

   static final class Builder {
      private String algorithm;
      private int    iterations;
      private int    saltSizeBytes;
      private byte[] digest;

      public Builder() {
      }

      public Builder algorithm(String val) {
         algorithm = val;
         return this;
      }

      public Builder iterations(int val) {
         iterations = val;
         return this;
      }

      public Builder saltSizeBytes(int val) {
         saltSizeBytes = val;
         return this;
      }

      public Builder digest(byte[] val) {
         digest = val;
         return this;
      }

      public DecodedPassword build() {
         return new DecodedPassword(this);
      }
   }
}
