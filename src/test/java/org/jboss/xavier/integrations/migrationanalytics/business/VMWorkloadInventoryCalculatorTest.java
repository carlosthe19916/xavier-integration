package org.jboss.xavier.integrations.migrationanalytics.business;

import org.apache.camel.test.spring.CamelSpringBootRunner;
import org.apache.camel.test.spring.UseAdviceWith;
import org.apache.commons.io.IOUtils;
import org.jboss.xavier.Application;
import org.jboss.xavier.analytics.pojo.input.VMWorkloadInventoryModel;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(CamelSpringBootRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@SpringBootTest(classes = {Application.class})
@UseAdviceWith // Disables automatic start of Camel context
@ActiveProfiles("test")
public class VMWorkloadInventoryCalculatorTest {
    @Inject
    VMWorkloadInventoryCalculator calculator;
    
    @Test
    public void calculate_jsonGiven_ShouldReturnCalculatedValues() throws IOException {
        String cloudFormsJson = IOUtils.resourceToString("cloudforms-export-v1.json", StandardCharsets.UTF_8, VMWorkloadInventoryCalculatorTest.class.getClassLoader());
        Map<String, Object> headers = new HashMap<>();
        
        Collection<VMWorkloadInventoryModel> modelList = calculator.calculate(cloudFormsJson, headers);
        assertThat(Integer.valueOf(modelList.size())).isEqualTo(24);
        assertThat(modelList.stream().filter(e -> e.getNicsCount() == 2).count()).isEqualTo(4);
        assertThat(modelList.stream().filter(e -> e.getVmName().equalsIgnoreCase("james-db-03-copy")).count()).isEqualTo(2);
        
        VMWorkloadInventoryModel expectedModel = new VMWorkloadInventoryModel();
        expectedModel.setVmName("dev-windows-server-2008");
        expectedModel.setProvider("VMware");
        expectedModel.setOsProductName("Windows Server 2008 R2 Enterprise");
        expectedModel.setNicsCount(1);
        expectedModel.setMemory(4294967296L);
        expectedModel.setHasRdmDisk(false);
        expectedModel.setGuestOSFullName("Windows Server 2008 R2 Enterprise");
        expectedModel.setDiskSpace(7437787136L);
        expectedModel.setDatacenter("V2V-DC");
        expectedModel.setCpuCores(1);
        expectedModel.setCluster("V2V_Cluster");
        
        assertThat(modelList.stream()).containsOnlyOnce( expectedModel);
    }
}