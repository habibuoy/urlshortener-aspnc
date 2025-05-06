using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UrlShortener.Migrations
{
    /// <inheritdoc />
    public partial class CreatorUserIdInUrl : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CreatorUserId",
                table: "Urls",
                type: "nvarchar(450)",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Urls_CreatorUserId",
                table: "Urls",
                column: "CreatorUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_Urls_AspNetUsers_CreatorUserId",
                table: "Urls",
                column: "CreatorUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Urls_AspNetUsers_CreatorUserId",
                table: "Urls");

            migrationBuilder.DropIndex(
                name: "IX_Urls_CreatorUserId",
                table: "Urls");

            migrationBuilder.DropColumn(
                name: "CreatorUserId",
                table: "Urls");
        }
    }
}
