package com.madbarsoft;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class EmployeeController {

    @GetMapping("/employee/info")
    public Map<String, String> getEmployeeInfo() {
        return Map.of(
            "employeeId", "12345",
            "name", "John Doe",
            "department", "Engineering"
        );
    }
}