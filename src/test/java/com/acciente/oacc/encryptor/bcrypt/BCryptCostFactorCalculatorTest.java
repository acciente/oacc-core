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

import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

public class BCryptCostFactorCalculatorTest {
   @Test
   public void testCostFactorStabilityOver100Runs() throws Exception {
      final int computedCostFactorMin      = 4;
      final int minComputeDurationInMillis = 100;

      int           lowestCostFactor   = Integer.MAX_VALUE;
      int           highestCostFactor  = Integer.MIN_VALUE;
      int           lastCostFactor     = 0;
      List<Integer> downVariationAtRun = new LinkedList<>();
      List<Integer> upVariationAtRun   = new LinkedList<>();
      int           i                  = 0;
      do {
         final int costFactor = BCryptCostFactorCalculator.calculateCostFactor(computedCostFactorMin, minComputeDurationInMillis);
         if (i == 0) {
            lowestCostFactor = costFactor;
            highestCostFactor = costFactor;
         }
         else {
            if (costFactor < lastCostFactor) {
               downVariationAtRun.add(i);
            }
            if (costFactor > lastCostFactor) {
               upVariationAtRun.add(i);
            }
            if (costFactor < lowestCostFactor) {
               lowestCostFactor = costFactor;
            }
            if (costFactor > highestCostFactor) {
               highestCostFactor = costFactor;
            }
         }
         lastCostFactor = costFactor;
         i++;
      } while (i < 100);

      assertThat("lowestCostFactor=" + lowestCostFactor + ", highestCostFactor=" + highestCostFactor +
                       ", downVariationAtRun=" + downVariationAtRun + ", upVariationAtRun=" + upVariationAtRun,
                 highestCostFactor - lowestCostFactor, lessThanOrEqualTo(1));
   }
}