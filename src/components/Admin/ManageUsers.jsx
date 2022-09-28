import { useRouter } from "next/router";
import { useState } from "react";
import { EditIcon } from "@chakra-ui/icons";
import {
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  TableContainer,
  Box,
  Input,
  Button
} from "@chakra-ui/react";


export default function ManageUsers({ users }) {
  const router = useRouter()

  const [enteredSearchInput, setEnteredSearchInput] = useState("");
  const enteredSearchHandler = (event) => {
    setEnteredSearchInput(event.target.value);
  };
  return (
    <Box>
      <Box display="flex" justifyContent="center">
        <Input
          placeholder="Search User"
          width="auto"
          marginTop="5px"
          onChange={enteredSearchHandler}
        />
      </Box>
      <Box display="flex" justifyContent="center">
        <TableContainer
          w="60rem"
          border="1px"
          borderColor="gray.400"
          rounded="md"
          boxShadow="md"
          m={5}
        >
          <Table variant="striped" colorScheme="blue" size="sm">
            <Thead>
              <Tr>
                <Th>Name</Th>
                <Th>Last Name</Th>
                <Th>DNI</Th>
                <Th>E-mail</Th>
                <Th>Role</Th>
                <Th>Edit User</Th>
              </Tr>
            </Thead>
            <Tbody>
              {users
                .filter((user) =>
                  user.name.toLowerCase().includes(enteredSearchInput.toLowerCase()) || user.lastname.toLowerCase().includes(enteredSearchInput.toLowerCase()) || user.dni.toString().toLowerCase().includes(enteredSearchInput.toLowerCase()) || user.email.toLowerCase().includes(enteredSearchInput.toLowerCase()) || user.role.toLowerCase().includes(enteredSearchInput.toLowerCase()))
                .map((user) => (
                  <Tr key={user._id}>
                    <Td>{user.name}</Td>
                    <Td>{user.lastname}</Td>
                    <Td>{user.dni}</Td>
                    <Td>{user.email}</Td>
                    <Td>{user.role}</Td>
                    <Td>
                      <Box>
                        <Button leftIcon={<EditIcon />} size="xs" onClick={() => { router.push(`/manage-users/${user._id}`) }}></Button>
                      </Box>
                    </Td>
                  </Tr>
                ))}
            </Tbody>
          </Table>
        </TableContainer>
      </Box>
    </Box>
  );
}
