package org.jboss.xavier.integrations.route;

import org.jboss.xavier.analytics.pojo.input.workload.inventory.VMWorkloadInventoryModel;
import org.jboss.xavier.integrations.route.strategy.WorkloadInventoryReportModelAggregationStrategy;
import org.springframework.beans.factory.annotation.Value;

import javax.inject.Named;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Named
public class VMWorkloadInventoryRoutes extends RouteBuilderExceptionHandler {

    @Value("${parallel.wir}")
    private boolean parallel;

    @Override
    public void configure() throws Exception {
        super.configure();

        from("direct:calculate-vmworkloadinventory").routeId("calculate-vmworkloadinventory")
            .setHeader("KieSessionId", constant("WorkloadInventoryKSession0"))
            .bean("VMWorkloadInventoryCalculator", "calculate(${body}, ${header.${type:org.jboss.xavier.integrations.route.MainRouteBuilder.MA_METADATA}})", false)
                .process(exchange -> {
                    Set<String> vmNamesWithSharedDisk = exchange.getIn().getHeader("vmNamesWithSharedDisk", Set.class);
                    Collection<VMWorkloadInventoryModel>  allVms = exchange.getIn().getBody(Collection.class);
                    Collection<VMWorkloadInventoryModel> originalAndAmendedVms = allVms.stream().map(vmWorkloadInventoryModel ->
                    {
                        if (vmNamesWithSharedDisk != null && vmNamesWithSharedDisk.contains(vmWorkloadInventoryModel.getVmName())) {
                            vmWorkloadInventoryModel.setHasSharedVmdk(true);
                        }
                        return vmWorkloadInventoryModel;
                    }).collect(Collectors.toList());
                    exchange.getIn().setBody(allVms);
                    exchange.getIn().removeHeader("vmNamesWithSharedDisk");
                    exchange.getIn().removeHeader("originalBody");
                })
                .split(body()).parallelProcessing(parallel).aggregationStrategy(new WorkloadInventoryReportModelAggregationStrategy())
                .setHeader(ANALYSIS_ID, simple("${body." + ANALYSIS_ID + "}", String.class))
                .removeHeader("vmNamesWithSharedDisk")
                .to("direct:vm-workload-inventory")
            .end()
            .process(exchange -> analysisService.addWorkloadInventoryReportModels(exchange.getIn().getBody(List.class),
                    Long.parseLong(exchange.getIn().getHeader(MA_METADATA, Map.class).get(ANALYSIS_ID).toString())));

        from ("direct:vm-workload-inventory").routeId("extract-vmworkloadinventory")
            .transform().method("decisionServerHelper", "generateCommands(${body}, \"GetWorkloadInventoryReports\", ${header.KieSessionId})")
            .to("direct:decisionserver").id("workload-decisionserver")
            .transform().method("decisionServerHelper", "extractWorkloadInventoryReportModel");
    }
}
