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
package com.acciente.oacc.sql.internal.persister.id;

public class Id<T> {
   private final long idValue;

   private Id(long idValue) {
      this.idValue = idValue;
   }

   public long getValue() {
      return idValue;
   }

   public static <T> Id<T> from(Long idValue) {
      if (idValue == null) {
         return null;
      }
      return new Id<>(idValue);
   }

   public static <T> Id<T> from(Integer idValue) {
      if (idValue == null) {
         return null;
      }
      return new Id<>(idValue);
   }

   @Override
   public boolean equals(Object other) {
      if (this == other) {
         return true;
      }
      if (other == null || getClass() != other.getClass()) {
         return false;
      }

      Id otherId = (Id) other;

      if (idValue != otherId.idValue) {
         return false;
      }

      return true;
   }

   @Override
   public int hashCode() {
      return (int) (idValue ^ (idValue >>> 32));
   }
}
