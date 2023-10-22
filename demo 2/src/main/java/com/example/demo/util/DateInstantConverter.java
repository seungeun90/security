package com.example.demo.util;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.time.Instant;
import java.time.LocalDateTime;

@Converter
public class DateInstantConverter  implements AttributeConverter<Instant, LocalDateTime> {
    @Override
    public LocalDateTime convertToDatabaseColumn(Instant attribute) {
        return null;
    }

    @Override
    public Instant convertToEntityAttribute(LocalDateTime dbData) {
        return null;
    }
}
