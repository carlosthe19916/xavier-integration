package org.jboss.xavier.analytics.pojo.output.workload.summary;

import com.fasterxml.jackson.annotation.JsonBackReference;

import javax.persistence.*;

@Entity
public class RecommendedTargetsIMSModel {

    @Id
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "report_id")
    @JsonBackReference
    private WorkloadSummaryReportModel report;

    private Integer total;
    private Integer rhv;
    private Integer rhel;
    private Integer osp;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public WorkloadSummaryReportModel getReport() {
        return report;
    }

    public void setReport(WorkloadSummaryReportModel report) {
        this.report = report;
    }

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public Integer getRhv() {
        return rhv;
    }

    public void setRhv(Integer rhv) {
        this.rhv = rhv;
    }

    public Integer getRhel() {
        return rhel;
    }

    public void setRhel(Integer rhel) {
        this.rhel = rhel;
    }

    public Integer getOsp() {
        return osp;
    }

    public void setOsp(Integer osp) {
        this.osp = osp;
    }
}
