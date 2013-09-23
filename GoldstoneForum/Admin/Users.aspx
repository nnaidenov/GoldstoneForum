<%@ Page Title="" Language="C#" MasterPageFile="~/Site.Master"
    AutoEventWireup="true" CodeBehind="Users.aspx.cs" Inherits="GoldstoneForum.Users" %>

<asp:Content ID="ContentUsers" ContentPlaceHolderID="MainContent" runat="server">
    <h2>Users</h2>
    <asp:GridView CssClass="table table-striped" ID="GridViewUsers" runat="server"
        AutoGenerateColumns="False" DataKeyNames="Id"
        PageSize="10" AllowPaging="true" AllowSorting="true"
        ItemType="GoldstoneForum.Models.ApplicationUser"
        SelectMethod="GridViewUsers_GetData">
        <Columns>
            <asp:BoundField DataField="UserName" HeaderText="UserName"
                SortExpression="UserName" />
            <asp:BoundField DataField="Email" HeaderText="Email"
                SortExpression="Email" />
            <asp:TemplateField HeaderText="Avatar">
                <ItemTemplate>
                    <asp:Image ImageUrl='<%# "~/Avatar_Files/" +Item.Avatar %>'
                        Height="100" runat="server" />
                </ItemTemplate>
            </asp:TemplateField>
            <asp:TemplateField HeaderText="Roles">
                <ItemTemplate>
                    <%# Item.Roles.FirstOrDefault() == null ? "User": Item.Roles.First().Role.Name%>
                </ItemTemplate>
            </asp:TemplateField>
            <asp:HyperLinkField Text="Edit..." HeaderText="Action"
                DataNavigateUrlFields="Id"
                DataNavigateUrlFormatString="EditUser.aspx?userId={0}" />
        </Columns>
    </asp:GridView>
</asp:Content>
