package com.badlogic.gdx.net;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.Set;

/* loaded from: classes.dex */
public final class HttpParametersUtils {
    public static String defaultEncoding = "UTF-8";
    public static String nameValueSeparator = "=";
    public static String parameterSeparator = "&";

    private HttpParametersUtils() {
    }

    public static String convertHttpParameters(Map<String, String> parameters) {
        Set<String> keySet = parameters.keySet();
        StringBuilder convertedParameters = new StringBuilder();
        for (String name : keySet) {
            convertedParameters.append(encode(name, defaultEncoding));
            convertedParameters.append(nameValueSeparator);
            convertedParameters.append(encode(parameters.get(name), defaultEncoding));
            convertedParameters.append(parameterSeparator);
        }
        if (convertedParameters.length() > 0) {
            convertedParameters.deleteCharAt(convertedParameters.length() - 1);
        }
        return convertedParameters.toString();
    }

    private static String encode(String content, String encoding) {
        try {
            return URLEncoder.encode(content, encoding);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}