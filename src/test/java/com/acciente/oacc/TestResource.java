package com.acciente.oacc;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestResource {
   @Test
   public void toString_resourceIdOnly() {
      final long resourceId = 123L;
      final String stringRepresentation = Resources.getInstance(resourceId).toString();
      assertThat(stringRepresentation, is("{resourceId: " + resourceId + "}"));
   }

   @Test
   public void toString_externalIdOnly() {
      final String externalId = "007";
      final String stringRepresentation = Resources.getInstance(externalId).toString();
      assertThat(stringRepresentation, is("{externalId: \"" + externalId + "\"}"));
   }

   @Test
   public void toString_resourceIdAndExternalId() {
      final long resourceId = 123L;
      final String externalId = "007";
      final String stringRepresentation = Resources.getInstance(resourceId, externalId).toString();
      assertThat(stringRepresentation, is("{resourceId: " + resourceId
                                                + ", externalId: \"" + externalId + "\"}"));
   }

   @Test
   public void toString_neitherResourceIdNorExternalId() {
      final String stringRepresentation = Resources.getInstance(null).toString();
      assertThat(stringRepresentation, is("{}"));
   }
}
