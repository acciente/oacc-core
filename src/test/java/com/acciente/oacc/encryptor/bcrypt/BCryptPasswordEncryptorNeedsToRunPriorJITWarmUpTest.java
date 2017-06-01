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

package com.acciente.oacc.encryptor.bcrypt;

import org.junit.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertTrue;

public class BCryptPasswordEncryptorNeedsToRunPriorJITWarmUpTest {

   @Test
   public void newInstanceUsingComputedCostFactorRunsAtLeastForMinComputeDuration() throws Exception {
      final int minComputeDurationInMs = 100;
      final int minCostFactor          = 4;
      final BCryptPasswordEncryptor passwordEncryptor
            = BCryptPasswordEncryptor.newInstance(BCryptCostFactorCalculator.calculateCostFactor(minCostFactor, minComputeDurationInMs));
      final char[] password = "opensesame".toCharArray();

      final long startTime = System.nanoTime();
      passwordEncryptor.encryptPassword(password);
      final long endTime      = System.nanoTime();
      final long durationInMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);

      final String message = "durationInMs: " + durationInMs +
            ", minComputeDurationInMs: " + minComputeDurationInMs +
            ", computedCostFactor: " + passwordEncryptor.getCostFactor();
      assertTrue(message, durationInMs > minComputeDurationInMs);
      System.out.println(message);
   }
}
