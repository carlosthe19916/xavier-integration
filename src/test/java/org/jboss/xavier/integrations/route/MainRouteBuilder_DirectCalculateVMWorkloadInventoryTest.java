package org.jboss.xavier.integrations.route;

import org.apache.camel.CamelContext;
import org.apache.camel.EndpointInject;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.test.spring.CamelSpringBootRunner;
import org.apache.camel.test.spring.MockEndpointsAndSkip;
import org.apache.camel.test.spring.UseAdviceWith;
import org.apache.commons.io.IOUtils;
import org.jboss.xavier.Application;
import org.jboss.xavier.analytics.pojo.input.workload.inventory.VMWorkloadInventoryModel;
import org.jboss.xavier.integrations.migrationanalytics.business.Calculator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(CamelSpringBootRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@MockEndpointsAndSkip("jms:queue:vm-workload-inventory")
@UseAdviceWith // Disables automatic start of Camel context
@SpringBootTest(classes = {Application.class})
@ActiveProfiles("test")
public class MainRouteBuilder_DirectCalculateVMWorkloadInventoryTest {
    @Inject
    CamelContext camelContext;

    @Inject
    MainRouteBuilder mainRouteBuilder;

    @EndpointInject(uri = "mock:jms:queue:vm-workload-inventory")
    private MockEndpoint mockJmsQueue;

    @Test
    public void mainRouteBuilder_DirectCalculate_JSONGiven_ShouldReturnExpectedCalculatedValues() throws Exception {
        //Given
        camelContext.setTracing(true);
        camelContext.setAutoStartup(false);

        String customerId = "CID123";
        String fileName = "cloudforms-export-v1.json";
        Integer sourceproductindicator = null;
        Double year1hypervisorpercentage = 10D;
        Double year2hypervisorpercentage = 20D;
        Double year3hypervisorpercentage = 30D;
        Double growthratepercentage = 7D;

        VMWorkloadInventoryModel expectedModel = new VMWorkloadInventoryModel();
        expectedModel.setVmName("dev-windows-server-2008-TEST");
        expectedModel.setProvider("VMware");
        expectedModel.setOsProductName("ServerNT");
        expectedModel.setNicsCount(1);
        expectedModel.setMemory(4294967296L);
        expectedModel.setHasRdmDisk(false);
        expectedModel.setGuestOSFullName("Microsoft Windows Server 2008 R2 (64-bit)");
        expectedModel.setDiskSpace(7437787136L);
        expectedModel.setDatacenter("V2V-DC");
        expectedModel.setCpuCores(1);
        expectedModel.setCluster("V2V_Cluster");
        expectedModel.setSystemServicesNames(Arrays.asList("{02B0078E-2148-45DD-B7D3-7E37AAB3B31D}","xmlprov","wudfsvc"));
        expectedModel.setVmDiskFilenames(Arrays.asList("[NFS_Datastore] dev-windows-server-2008/dev-windows-server-2008.vmdk"));

        HashMap<String, String> files = new HashMap<>();
        files.put("/root/.bash_profile","# .bash_profile\n\n# Get the aliases and functions\nif [ -f ~/.bashrc ]; then\n\t. ~/.bashrc\nfi\n\n# User specific environment and startup programs\n\nPATH=$PATH:$HOME/bin\nexport PATH\nexport JAVA_HOME=/usr/java/jdk1.5.0_07/bin/java\nexport WAS_HOME=/opt/IBM/WebSphere/AppServer\n");
        files.put("/opt/IBM", null);
        expectedModel.setFiles(files);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("filename", fileName);
        metadata.put("org_id", customerId);
        metadata.put(Calculator.YEAR_1_HYPERVISORPERCENTAGE, year1hypervisorpercentage);
        metadata.put(Calculator.YEAR_2_HYPERVISORPERCENTAGE, year2hypervisorpercentage);
        metadata.put(Calculator.YEAR_3_HYPERVISORPERCENTAGE, year3hypervisorpercentage);
        metadata.put(Calculator.GROWTHRATEPERCENTAGE, growthratepercentage);

        Map<String, Object> headers = new HashMap<>();
        headers.put("MA_metadata", metadata);

        //When
        camelContext.start();
        camelContext.startRoute("calculate-vmworkloadinventory");
        String body = IOUtils.resourceToString(fileName, StandardCharsets.UTF_8, this.getClass().getClassLoader());
        
        camelContext.createProducerTemplate().sendBodyAndHeaders("direct:calculate-vmworkloadinventory", body, headers);

        Thread.sleep(5000);
        
        //Then
        assertThat(mockJmsQueue.getExchanges().stream().map(e -> e.getIn().getBody(VMWorkloadInventoryModel.class)).filter(e -> e.getVmName().equalsIgnoreCase("dev-windows-server-2008-TEST")).findFirst().get()).isEqualToComparingFieldByFieldRecursively(expectedModel);
        assertThat(mockJmsQueue.getExchanges().size()).isEqualTo(21);

        camelContext.stop();
    }

}