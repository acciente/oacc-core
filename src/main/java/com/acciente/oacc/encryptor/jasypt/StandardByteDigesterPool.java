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

import org.jasypt.digest.StandardByteDigester;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keeps a pool of Jasypt digester instances, there is one instance in the pool per unique digester configuration.
 */
class StandardByteDigesterPool {
   private final Map<String, Map<Integer, Map<Integer, StandardByteDigester>>> algorithmMap = new ConcurrentHashMap<>();

   public StandardByteDigester getStandardByteDigester(String algorithm, int iterations, int saltSizeBytes) {
      final Map<Integer, StandardByteDigester> saltSizeBytesMap = getInnerMap(getInnerMap(algorithmMap, algorithm), iterations);

      StandardByteDigester standardByteDigester = saltSizeBytesMap.get(saltSizeBytes);
      if (standardByteDigester == null) {
         standardByteDigester = newStandardByteDigester(algorithm, iterations, saltSizeBytes);
         saltSizeBytesMap.put(saltSizeBytes, standardByteDigester);
      }

      return standardByteDigester;
   }

   private static <K, IK, IV> Map<IK, IV> getInnerMap(Map<K, Map<IK, IV>> outerMap, K outerKey) {
      Map<IK, IV> innerMap = outerMap.get(outerKey);
      if (innerMap == null) {
         innerMap = new ConcurrentHashMap<>();
         outerMap.put(outerKey, innerMap);
      }
      return innerMap;
   }

   private static StandardByteDigester newStandardByteDigester(String algorithm, int iterations, int saltSizeBytes) {
      final StandardByteDigester standardByteDigester = new StandardByteDigester();
      standardByteDigester.setAlgorithm(algorithm);
      standardByteDigester.setIterations(iterations);
      standardByteDigester.setSaltSizeBytes(saltSizeBytes);
      standardByteDigester.initialize();
      return standardByteDigester;
   }
}
