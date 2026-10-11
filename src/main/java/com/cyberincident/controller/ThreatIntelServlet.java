package com.cyberincident.controller;

import com.cyberincident.security.ThreatIntelService;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

/**
 * REST Endpoint for Threat Intelligence, IOC lookups, and MITRE ATT&CK Playbook generators.
 */
@WebServlet("/ThreatIntelServlet")
public class ThreatIntelServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        if ("feed".equalsIgnoreCase(action)) {
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter out = response.getWriter();
            List<Map<String, String>> feed = ThreatIntelService.getLiveThreatFeed();
            
            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < feed.size(); i++) {
                Map<String, String> item = feed.get(i);
                json.append("{")
                    .append("\"id\":\"").append(escape(item.get("id"))).append("\",")
                    .append("\"severity\":\"").append(escape(item.get("severity"))).append("\",")
                    .append("\"title\":\"").append(escape(item.get("title"))).append("\",")
                    .append("\"source\":\"").append(escape(item.get("source"))).append("\",")
                    .append("\"advisory\":\"").append(escape(item.get("advisory"))).append("\"")
                    .append("}");
                if (i < feed.size() - 1) json.append(",");
            }
            json.append("]");
            out.print(json.toString());
            out.flush();
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown action");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String indicator = request.getParameter("indicator");
        ThreatIntelService.IocReport report = ThreatIntelService.analyzeIndicator(indicator);

        response.setContentType("application/json;charset=UTF-8");
        PrintWriter out = response.getWriter();

        StringBuilder json = new StringBuilder("{");
        json.append("\"indicator\":\"").append(escape(report.getIndicator())).append("\",");
        json.append("\"type\":\"").append(escape(report.getType())).append("\",");
        json.append("\"threatScore\":\"").append(escape(report.getThreatScore())).append("\",");
        json.append("\"actor\":\"").append(escape(report.getActor())).append("\",");
        json.append("\"mitreTechnique\":\"").append(escape(report.getMitreTechnique())).append("\",");
        json.append("\"recommendedAction\":\"").append(escape(report.getRecommendedAction())).append("\",");
        json.append("\"containmentCommands\":[");
        for (int i = 0; i < report.getContainmentCommands().size(); i++) {
            json.append("\"").append(escape(report.getContainmentCommands().get(i))).append("\"");
            if (i < report.getContainmentCommands().size() - 1) json.append(",");
        }
        json.append("]}");

        out.print(json.toString());
        out.flush();
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
