<%@ page contentType="application/json; charset=UTF-8" %>

<% String test = "test";
    String testValue = request.getParameter(test);
    response.setContentType("application/json");

    if (testValue != null) {
        if (testValue.equals("secret1")){
            response.getWriter().write("{\"flag\":\"S2G{f4ke_fl4g}\"}");
        } else {
            response.getWriter().write("{\"flag\":\"sry >:)\"}");
        }
    } else {
        response.getWriter().write("{\"flag\":\"sry:(\"}");
    }
%>