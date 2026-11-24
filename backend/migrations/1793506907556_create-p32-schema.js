export function up(pgm) {
    pgm.sql(`
    CREATE SCHEMA p32 AUTHORIZATION p32_migrator;

    REVOKE ALL ON SCHEMA p32 FROM PUBLIC;

    GRANT USAGE ON SCHEMA p32 TO p32_app;
  `)
}

export function down(pgm) {
    // Refuse rollback if the schema still contains objects.
    pgm.sql('DROP SCHEMA p32 RESTRICT;')
}