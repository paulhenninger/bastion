package dev.bastion.email;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A well-formed email address by {@link EmailAddress}'s rules, reporting the specific
 * problem ("the email domain must include a top-level domain") rather than a generic
 * "invalid email". Includes the not-blank and length checks.
 */
@Documented
@Constraint(validatedBy = ValidEmail.Validator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidEmail {

    String message() default "Enter a valid email address";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidEmail, String> {
        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            String problem = EmailAddress.problem(value);
            if (problem == null) {
                return true;
            }
            context.disableDefaultConstraintViolation();
            // Messages pass through the EL template engine; escape its delimiters.
            context.buildConstraintViolationWithTemplate(
                            problem.replace("\\", "\\\\").replace("$", "\\$").replace("{", "\\{").replace("}", "\\}"))
                    .addConstraintViolation();
            return false;
        }
    }
}
